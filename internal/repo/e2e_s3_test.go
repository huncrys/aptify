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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/aptify/internal/repofs/s3test"
)

// s3Config is what the bucket builds: two architectures, an architecture `all`
// package folded into both, changelogs and by-hash, so that every stage that
// touches the storage runs.
func s3Config(t *testing.T) *v1alpha1.Repository {
	t.Helper()

	conf := singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_1.0_arm64.deb"),
		debPath(t, "hello-world_3.0_all.deb"))

	conf.URL = testRepositoryURL
	conf.Changelogs = true
	conf.ByHash.Enabled = true

	return conf
}

// buildInto runs a build against the repository, reporting what it asked of
// the storage.
func buildInto(t *testing.T, fsys repofs.FS, confPath string, force, reread bool) *countingFS {
	t.Helper()

	counted := counting(fsys)

	require.NoError(t, Build(Options{
		FS:             counted,
		ConfigPath:     confPath,
		PrivateKeyPath: testKeyPath(t),
		Force:          force,
		Reread:         reread,
	}))

	return counted
}

// TestS3BuildPublishesAUsableRepository drives the whole pipeline against a
// bucket and checks the same thing the local end to end suite checks: a client
// could use what came out. Nothing about the repository is read from a local
// copy, because there is none.
func TestS3BuildPublishesAUsableRepository(t *testing.T) {
	fsys := s3test.FS(t)
	confPath := writeTestConfig(t, s3Config(t))

	counted := buildInto(t, fsys, confPath, false, false)

	verifyRepoFS(t, fsys, testReleaseName)

	// The pool holds one object per package, uploaded once, and never read
	// back: the metadata and the checksums come from the local source file.
	assert.Zero(t, counted.poolReads, "a freshly ingested package was read back out of the bucket")

	for _, name := range []string{
		"pool/stable/h/hello-world/hello-world_1.0_amd64.deb",
		"pool/stable/h/hello-world/hello-world_1.0_arm64.deb",
		"pool/stable/h/hello-world/hello-world_3.0_all.deb",
		"signing_key.asc",
		"changelogs/stable/h/hello-world/hello-world_1.0.changelog",
		"changelogs/stable/h/hello-world/hello-world_3.0.changelog",
	} {
		_, err := fs.Stat(fsys, name)
		require.NoError(t, err, "%s was not published", name)
	}

	// Architecture `all` is folded into every architecture rather than
	// published as one of its own, here as anywhere else.
	for _, architecture := range []string{"amd64", "arm64"} {
		packages := decodePackagesFS(t, fsys,
			distName(testReleaseName, testComponentName, "binary-"+architecture, "Packages"))

		require.Len(t, packages, 2)
		assert.Contains(t, packageVersions(packages), "hello-world 3.0 all")

		for _, pkg := range packages {
			_, err := fs.Stat(fsys, pkg.Filename)
			require.NoError(t, err, "%s names a pool file that is not published", pkg.Filename)
		}
	}

	_, err := fs.Stat(fsys, distName(testReleaseName, testComponentName, "binary-all"))
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestS3RebuildTouchesNothing pins incrementality where it costs the most: a
// rebuild of an unchanged repository issues no PUT, no copy, no delete and no
// touch, and leaves every recorded modification time alone.
func TestS3RebuildTouchesNothing(t *testing.T) {
	fsys := s3test.FS(t)
	confPath := writeTestConfig(t, s3Config(t))

	buildInto(t, fsys, confPath, false, false)

	before := snapshotTreeFS(t, fsys)

	counted := buildInto(t, fsys, confPath, false, false)

	assert.Zero(t, counted.writes, "an unchanged rebuild published something")
	assert.Zero(t, counted.clones, "an unchanged rebuild republished the by-hash tree")
	assert.Zero(t, counted.removes, "an unchanged rebuild deleted something")
	assert.Zero(t, counted.chtimes, "an unchanged rebuild touched something")
	assert.Zero(t, counted.poolReads, "an unchanged rebuild read the pool")

	assert.Equal(t, before, snapshotTreeFS(t, fsys))

	// --force regenerates every indice and still publishes nothing, since the
	// bytes are unchanged.
	counted = buildInto(t, fsys, confPath, true, false)

	assert.Zero(t, counted.writes)
	assert.Equal(t, before, snapshotTreeFS(t, fsys))
}

// TestS3IncrementalBuild covers the point of the whole exercise: adding a
// package to a repository nobody holds a copy of transfers the new objects and
// the indices that name them, and leaves everything else where it is.
func TestS3IncrementalBuild(t *testing.T) {
	fsys := s3test.FS(t)

	buildInto(t, fsys, writeTestConfig(t, s3Config(t)), false, false)

	before := snapshotTreeFS(t, fsys)

	conf := s3Config(t)
	conf.Releases[0].Components[0].Packages = append(conf.Releases[0].Components[0].Packages,
		debPath(t, "hello-world_2.0_amd64.deb"))

	buildInto(t, fsys, writeTestConfig(t, conf), false, false)

	verifyRepoFS(t, fsys, testReleaseName)

	after := snapshotTreeFS(t, fsys)

	// The new package, and nothing else, is added to the pool.
	assert.Equal(t, "pool/stable/h/hello-world/hello-world_2.0_amd64.deb",
		onlyAddedUnder(t, "pool/", before, after))

	// The architecture that gained nothing keeps its indices byte for byte,
	// modification times included.
	for _, name := range []string{
		distName(testReleaseName, testComponentName, "binary-arm64", "Packages"),
		distName(testReleaseName, testComponentName, "binary-arm64", "Packages.gz"),
		distName(testReleaseName, testComponentName, "Contents-arm64"),
	} {
		assert.Equal(t, before[name], after[name], "%s was republished", name)
	}

	// The one that did is republished, and the release with it.
	packagesName := distName(testReleaseName, testComponentName, "binary-amd64", "Packages")
	assert.NotEqual(t, before[packagesName], after[packagesName])

	inRelease := path.Join("dists", testReleaseName, "InRelease")
	assert.NotEqual(t, before[inRelease], after[inRelease])

	assert.Equal(t, []string{"hello-world 1.0 amd64", "hello-world 2.0 amd64", "hello-world 3.0 all"},
		packageVersions(decodePackagesFS(t, fsys, packagesName)))
}

// TestS3OneOffAddAndRemove drives the imperative commands against a bucket:
// they publish and withdraw a single package without a local copy of the
// repository, and pay the same way an incremental build does - the added .deb
// is uploaded rather than read back, the architecture that gained nothing keeps
// its indices, and the removal leaves the amd64 indice byte for byte what it
// was before the add.
func TestS3OneOffAddAndRemove(t *testing.T) {
	fsys := s3test.FS(t)
	confPath := writeTestConfig(t, s3Config(t))

	buildInto(t, fsys, confPath, false, false)

	before := snapshotTreeFS(t, fsys)

	added := debPath(t, "hello-world_2.0_amd64.deb")

	counted := counting(fsys)
	require.NoError(t, Add(AddOptions{
		Options: Options{
			FS:             counted,
			ConfigPath:     confPath,
			PrivateKeyPath: testKeyPath(t),
		},
		Packages: []string{added},
	}))

	assert.Zero(t, counted.poolReads, "a one-off add read a package back out of the bucket")

	verifyRepoFS(t, fsys, testReleaseName)

	packagesName := distName(testReleaseName, testComponentName, "binary-amd64", "Packages")
	poolName := "pool/stable/h/hello-world/hello-world_2.0_amd64.deb"

	after := snapshotTreeFS(t, fsys)
	assert.Equal(t, poolName, onlyAddedUnder(t, "pool/", before, after))
	assert.Equal(t, []string{"hello-world 1.0 amd64", "hello-world 2.0 amd64", "hello-world 3.0 all"},
		packageVersions(decodePackagesFS(t, fsys, packagesName)))

	for _, name := range []string{
		distName(testReleaseName, testComponentName, "binary-arm64", "Packages"),
		distName(testReleaseName, testComponentName, "Contents-arm64"),
	} {
		assert.Equal(t, before[name], after[name], "%s was republished", name)
	}

	counted = counting(fsys)
	require.NoError(t, Remove(RemoveOptions{
		Options: Options{
			FS:             counted,
			ConfigPath:     confPath,
			PrivateKeyPath: testKeyPath(t),
		},
		Selectors: []string{"hello-world=2.0"},
	}))

	assert.Zero(t, counted.poolReads, "a one-off removal read the pool")

	verifyRepoFS(t, fsys, testReleaseName)

	_, err := fs.Stat(fsys, poolName)
	assert.ErrorIs(t, err, fs.ErrNotExist, "the withdrawn package was left in the pool")

	// The indice holds what it held before the package was ever added, and
	// because those are the bytes already published it was not rewritten.
	assert.Equal(t, before[packagesName], snapshotTreeFS(t, fsys)[packagesName])
}

// TestS3ByHashSurvivesAReplacedIndice pins what by-hash is for, on storage
// where a copy is a copy rather than a link: a client holding the previous
// release can still fetch the index it named after a later build replaced it.
func TestS3ByHashSurvivesAReplacedIndice(t *testing.T) {
	fsys := s3test.FS(t)

	buildInto(t, fsys, writeTestConfig(t, s3Config(t)), false, false)

	released := decodeReleaseFS(t, mustSub(t, fsys, path.Join("dists", testReleaseName)), "InRelease",
		openpgp.EntityList{testEntity(t)})

	const indice = "stable/binary-amd64/Packages"

	var superseded []byte
	for _, entry := range released.SHA256 {
		if entry.Filename != indice {
			continue
		}

		var err error
		superseded, err = fs.ReadFile(fsys, path.Join("dists", testReleaseName, indice))
		require.NoError(t, err)

		conf := s3Config(t)
		conf.Releases[0].Components[0].Packages = append(conf.Releases[0].Components[0].Packages,
			debPath(t, "hello-world_2.0_amd64.deb"))

		buildInto(t, fsys, writeTestConfig(t, conf), false, false)

		// The index itself has moved on.
		current, err := fs.ReadFile(fsys, path.Join("dists", testReleaseName, indice))
		require.NoError(t, err)
		require.NotEqual(t, superseded, current)

		// What the release a client read named is still there, and still holds
		// what that release described.
		byHash, err := fs.ReadFile(fsys, path.Join("dists", testReleaseName,
			"stable/binary-amd64/by-hash/SHA256", entry.Hash))
		require.NoError(t, err)
		assert.Equal(t, superseded, byHash)

		return
	}

	t.Fatalf("the release does not name %s", indice)
}

// TestS3Inspect checks that a bucket can be read back without building
// anything, which is the other half of the repository being its own state
// store.
func TestS3Inspect(t *testing.T) {
	fsys := s3test.FS(t)

	buildInto(t, fsys, writeTestConfig(t, s3Config(t)), false, false)

	var buf bytes.Buffer
	require.NoError(t, Inspect(fsys, &buf))

	var inspected []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &inspected))

	var listed []string
	for _, pkg := range inspected {
		listed = append(listed, fmt.Sprintf("%v %v %v", pkg["Package"], pkg["Version"], pkg["Architecture"]))
	}
	slices.Sort(listed)

	assert.Equal(t, []string{
		"hello-world 1.0 amd64",
		"hello-world 1.0 arm64",
		"hello-world 3.0 all",
	}, listed)
}

// TestS3RereadReadsThePool pins the documented cost of --reread: it is the one
// ordinary switch that downloads every published package.
func TestS3RereadReadsThePool(t *testing.T) {
	fsys := s3test.FS(t)
	confPath := writeTestConfig(t, s3Config(t))

	buildInto(t, fsys, confPath, false, false)

	counted := buildInto(t, fsys, confPath, false, true)

	assert.Positive(t, counted.poolReads, "--reread did not read the pool")

	// Reading them all back describes the same repository, so nothing is
	// republished.
	assert.Zero(t, counted.writes, "rereading an unchanged repository republished something")

	verifyRepoFS(t, fsys, testReleaseName)
}

// TestS3ResolvesTheBackendFromTheURL checks the selection the CLI makes: an
// s3:// target is a bucket, anything else a directory.
func TestS3ResolvesTheBackendFromTheURL(t *testing.T) {
	dir := t.TempDir()

	fsys, err := repofs.New(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, dir, fsys.Name())
	assert.True(t, repofs.IsS3URL("s3://bucket/prefix"))
	assert.False(t, repofs.IsS3URL(dir))
}
