// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2026 Kristof Bach <crys@crys.hu>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package repo

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
)

// demoConfig is the configuration of examples/demo.yaml, with the packages
// named absolutely because a build resolves the globs against the process
// working directory.
func demoConfig(t *testing.T) *v1alpha1.Repository {
	t.Helper()

	var explicit []string
	for _, name := range []string{
		"hello-world_1.0_amd64.deb",
		"hello-world_1.0_arm64.deb",
		"hello-world_2.0_amd64.deb",
		"hello-world_2.0_arm64.deb",
	} {
		explicit = append(explicit, debPath(t, name))
	}

	glob, err := filepath.Abs(filepath.Join(testdataDir, "package", "hello-world_*.deb"))
	require.NoError(t, err)

	return &v1alpha1.Repository{
		Releases: []v1alpha1.ReleaseConfig{
			{
				Name:        "bookworm",
				Version:     "12",
				Origin:      "Demo Organization",
				Label:       "Demo",
				Suite:       "bookworm",
				Description: "Demo repository",
				Components: []v1alpha1.ComponentConfig{
					{Name: "stable", Packages: explicit},
				},
			},
			{
				Name:    "bookworm-max-versions",
				Version: "12",
				Origin:  "Demo Organization",
				Label:   "Demo",
				Suite:   "bookworm",
				Components: []v1alpha1.ComponentConfig{
					{Name: "stable", Packages: []string{glob}, MaxVersions: 1},
				},
			},
		},
	}
}

// TestBuildFreshRepository drives the whole pipeline against an empty
// directory and pins what a client is handed: verifiable releases, the standard
// pool layout, the pin keys of the per architecture Release stub, and the
// digest fields a Packages stanza has to carry. It also pins the arch `all`
// fold - `all` is published inside every architecture's indices, never as an
// architecture of its own.
func TestBuildFreshRepository(t *testing.T) {
	repoDir := t.TempDir()
	confPath := writeTestConfig(t, demoConfig(t))

	mustBuild(t, repoDir, confPath, false, false)

	verifyRepo(t, repoDir, "bookworm", "bookworm-max-versions")

	// Standard Debian pool layout: pool/<component>/<prefix>/<source>/.
	poolDir := filepath.Join(repoDir, "pool", "stable", "h", "hello-world")
	for _, name := range []string{
		"hello-world_1.0_amd64.deb",
		"hello-world_1.0_arm64.deb",
		"hello-world_2.0_amd64.deb",
		"hello-world_2.0_arm64.deb",
		// Kept by the second release, whose max_versions leaves 3.0 alone.
		"hello-world_3.0_all.deb",
	} {
		require.FileExists(t, filepath.Join(poolDir, name))
	}

	// The public key is published with the private key's modification time, so
	// that a rebuild does not churn a mirror.
	keyInfo, err := os.Stat(testKeyPath(t))
	require.NoError(t, err)

	publishedKeyInfo, err := os.Stat(filepath.Join(repoDir, "signing_key.asc"))
	require.NoError(t, err)
	assert.Equal(t, keyInfo.ModTime(), publishedKeyInfo.ModTime())

	// The stub carries apt's pin keys and nothing else: no Description, and no
	// Acquire-By-Hash while by-hash is off.
	for _, architecture := range []string{"amd64", "arm64"} {
		stubPath := filepath.Join(repoDir, "dists", "bookworm", "stable", "binary-"+architecture, "Release")

		assert.Equal(t, []string{
			"Archive", "Origin", "Label", "Version", "Component", "Architecture",
		}, stanzaFields(t, stubPath), "component Release stub of %s", architecture)

		stub := decodeComponentRelease(t, stubPath)
		assert.Equal(t, "bookworm", stub.Archive)
		assert.Equal(t, "Demo Organization", stub.Origin)
		assert.Equal(t, "Demo", stub.Label)
		assert.Equal(t, "12", stub.Version)
		assert.Equal(t, "stable", stub.Component)
		assert.Equal(t, architecture, stub.Architecture.String())
	}

	// Every stanza carries what a client needs to fetch and verify the .deb,
	// plus the description digest apt indexes translations by.
	for _, architecture := range []string{"amd64", "arm64"} {
		packages := decodePackages(t,
			filepath.Join(repoDir, "dists", "bookworm", "stable", "binary-"+architecture, "Packages"))

		require.Len(t, packages, 2, "binary-%s of bookworm", architecture)

		for _, pkg := range packages {
			assert.Equal(t, "hello-world", pkg.Name)
			assert.Equal(t, architecture, pkg.Architecture.String())
			assert.Equal(t,
				filepath.ToSlash(filepath.Join("pool", "stable", "h", "hello-world",
					"hello-world_"+pkg.Version.String()+"_"+architecture+".deb")),
				pkg.Filename)
			require.FileExists(t, filepath.Join(repoDir, filepath.FromSlash(pkg.Filename)))

			assert.NotZero(t, pkg.Size)
			assert.NotEmpty(t, pkg.SHA256)
			assert.NotEmpty(t, pkg.MD5sum)
			assert.NotEmpty(t, pkg.SHA1)
			assert.NotEmpty(t, pkg.DescriptionMD5)
		}
	}

	// max_versions judges a package the way a client sees it, so the arch `all`
	// 3.0 outranks every architecture's own versions and is the only thing left
	// - folded into each architecture's indices rather than published as an
	// architecture of its own.
	for _, architecture := range []string{"amd64", "arm64"} {
		packages := decodePackages(t,
			filepath.Join(repoDir, "dists", "bookworm-max-versions", "stable", "binary-"+architecture, "Packages"))

		require.Len(t, packages, 1)
		assert.Equal(t, "3.0", packages[0].Version.String())
		assert.Equal(t, "all", packages[0].Architecture.String())
	}

	assert.NoDirExists(t, filepath.Join(repoDir, "dists", "bookworm-max-versions", "stable", "binary-all"))
	assert.NoFileExists(t, filepath.Join(repoDir, "dists", "bookworm-max-versions", "stable", "Contents-all"))
}

// TestBuildIsIdempotent pins the invariant every incremental skip exists for:
// rebuilding an unchanged repository republishes nothing, so a mirror sees
// neither new bytes nor new modification times.
func TestBuildIsIdempotent(t *testing.T) {
	repoDir := t.TempDir()
	confPath := writeTestConfig(t, demoConfig(t))

	mustBuild(t, repoDir, confPath, false, false)
	before := snapshotTree(t, repoDir)

	mustBuild(t, repoDir, confPath, false, false)
	after := snapshotTree(t, repoDir)

	require.Equal(t, before, after)
}

// stanzaFields returns the field names of a single stanza file, in the order
// they are published in.
func stanzaFields(t *testing.T, filePath string) []string {
	t.Helper()

	body, err := os.ReadFile(filePath)
	require.NoError(t, err)

	var fields []string
	for _, line := range strings.Split(string(body), "\n") {
		if line == "" || strings.HasPrefix(line, " ") {
			continue
		}

		name, _, ok := strings.Cut(line, ":")
		require.True(t, ok, "not a stanza line: %q", line)

		fields = append(fields, name)
	}

	return fields
}

func decodeComponentRelease(t *testing.T, filePath string) types.ComponentRelease {
	t.Helper()

	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	decoder, err := deb822.NewDecoder(f, nil)
	require.NoError(t, err)

	var stub types.ComponentRelease
	require.NoError(t, decoder.Decode(&stub))

	return stub
}

func decodePackages(t *testing.T, filePath string) []types.Package {
	t.Helper()

	dir, name := filepath.Split(filePath)

	return decodePackagesFS(t, os.DirFS(dir), name)
}

// decodePackagesFS is the same read of an indice published anywhere.
func decodePackagesFS(t *testing.T, fsys fs.FS, name string) []types.Package {
	t.Helper()

	f, err := fsys.Open(name)
	require.NoError(t, err)
	defer f.Close()

	decoder, err := deb822.NewDecoder(f, nil)
	require.NoError(t, err)

	var packages []types.Package
	require.NoError(t, decoder.Decode(&packages))

	return packages
}
