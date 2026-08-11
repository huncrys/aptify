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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822"
)

// testRepositoryURL is where the configurations below claim to be served from,
// which is what makes the Changelogs field of the release resolvable.
const testRepositoryURL = "https://apt.example.com"

// changelogConfig publishes changelogs, which takes both the switch and a URL
// to advertise them under.
func changelogConfig(maxVersions uint, packages ...string) *v1alpha1.Repository {
	conf := singleComponentConfig(maxVersions, packages...)
	conf.URL = testRepositoryURL
	conf.Changelogs = true

	return conf
}

// changelogPath is where a published changelog lives: named from the source
// package and its version, never from the binary package or architecture.
func changelogPath(repoDir, source, version string) string {
	prefix := source[:1]

	return filepath.Join(repoDir, "changelogs", testComponentName, prefix, source,
		fmt.Sprintf("%s_%s.changelog", source, version))
}

// TestChangelogsPublishExtractedEntries pins what the Changelogs URL in the
// release resolves to: the changelog the package actually ships, named from
// the source package, and kept at the modification time it had in the archive
// so that a rebuild does not churn a mirror.
func TestChangelogsPublishExtractedEntries(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, changelogConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb"),
	))

	mustBuild(t, repoDir, confPath, false, false)

	release := decodeRelease(t, filepath.Join(repoDir, "dists", testReleaseName, "Release"), nil)
	assert.Equal(t, testRepositoryURL+"/changelogs/@CHANGEPATH@.changelog", release.Changelogs)

	for version, change := range map[string]string{
		"1.0": "  * Initial release.",
		"2.0": "  * Another release.",
	} {
		body, err := os.ReadFile(changelogPath(repoDir, "hello-world", version))
		require.NoError(t, err, "no changelog published for %s", version)

		assert.Contains(t, string(body), fmt.Sprintf("hello-world (%s) unstable; urgency=medium", version))
		assert.Contains(t, string(body), change)
	}

	// The mtimes come from the archive, so a rebuild leaves every changelog
	// exactly as it was.
	before := snapshotTree(t, filepath.Join(repoDir, "changelogs"))

	mustBuild(t, repoDir, confPath, false, false)

	assert.Equal(t, before, snapshotTree(t, filepath.Join(repoDir, "changelogs")))
}

// TestChangelogsFallBackToPlaceholder pins the fallback: a package shipping no
// changelog still gets one, so that the URL the release advertises resolves to
// something apt can parse. Its exact shape is pinned by
// changelog_placeholder_test.go.
func TestChangelogsFallBackToPlaceholder(t *testing.T) {
	repoDir := t.TempDir()

	debFile := buildTestDeb(t, t.TempDir(), debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		files: map[string]string{"usr/bin/demo-tool": "one\n"},
	})

	mustBuild(t, repoDir, writeTestConfig(t, changelogConfig(0, debFile)), false, false)

	body, err := os.ReadFile(changelogPath(repoDir, "demo-tool", "1.0"))
	require.NoError(t, err)

	assert.Contains(t, string(body), "demo-tool (1.0) unstable; urgency=medium")
	assert.Contains(t, string(body), "  * No changelog available.")
}

// TestChangelogsPreferTheSourceNamedPackage pins which of the binary packages
// of one source provides the single changelog they all map onto: the one named
// after the source, whatever order the component lists them in. A dbgsym ships
// its documentation directory as a symlink, so letting it win would cost the
// real changelog; on its own there is nothing to extract and the placeholder is
// what keeps the advertised URL resolvable.
func TestChangelogsPreferTheSourceNamedPackage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		packages    []string
		wantChanges string
	}{
		{
			name:        "dbgsym alone",
			packages:    []string{"hello-world-dbgsym_1.0_amd64.deb"},
			wantChanges: "  * No changelog available.",
		},
		{
			name:        "binary package listed first",
			packages:    []string{"hello-world_1.0_amd64.deb", "hello-world-dbgsym_1.0_amd64.deb"},
			wantChanges: "  * Initial release.",
		},
		{
			name:        "dbgsym listed first",
			packages:    []string{"hello-world-dbgsym_1.0_amd64.deb", "hello-world_1.0_amd64.deb"},
			wantChanges: "  * Initial release.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repoDir := t.TempDir()

			packages := make([]string, 0, len(tc.packages))
			for _, name := range tc.packages {
				packages = append(packages, debPath(t, name))
			}

			mustBuild(t, repoDir, writeTestConfig(t, changelogConfig(0, packages...)), false, false)

			// Named from the source, so the dbgsym publishes nothing of its own.
			assert.NoFileExists(t, changelogPath(repoDir, "hello-world-dbgsym", "1.0"))

			body, err := os.ReadFile(changelogPath(repoDir, "hello-world", "1.0"))
			require.NoError(t, err)

			assert.Contains(t, string(body), "hello-world (1.0) unstable; urgency=medium")
			assert.Contains(t, string(body), tc.wantChanges)
		})
	}
}

// TestChangelogsSkipMissingPoolFiles pins the one case that publishes nothing:
// a package whose .deb has gone from the pool cannot be read, which is not the
// same as it shipping no changelog, and a placeholder would assert that the
// version has nothing to report.
func TestChangelogsSkipMissingPoolFiles(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, changelogConfig(0, debPath(t, "hello-world_1.0_amd64.deb")))
	mustBuild(t, repoDir, confPath, false, false)

	published := changelogPath(repoDir, "hello-world", "1.0")
	require.FileExists(t, published)
	require.NoError(t, os.Remove(published))

	packages := packagesIn(t, repoDir, "amd64")
	require.Len(t, packages, 1)
	require.NoError(t, os.Remove(filepath.Join(repoDir, filepath.FromSlash(packages[0].Filename))))

	mustBuild(t, repoDir, confPath, false, false)

	assert.NoFileExists(t, published)
}

// TestChangelogsPruneUnreferenced pins the sweep: the changelog of a version
// the build dropped goes with it, and the one still published stays.
func TestChangelogsPruneUnreferenced(t *testing.T) {
	repoDir := t.TempDir()

	packages := []string{
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb"),
	}

	mustBuild(t, repoDir, writeTestConfig(t, changelogConfig(0, packages...)), false, false)

	require.FileExists(t, changelogPath(repoDir, "hello-world", "1.0"))
	require.FileExists(t, changelogPath(repoDir, "hello-world", "2.0"))

	mustBuild(t, repoDir, writeTestConfig(t, changelogConfig(1, packages...)), false, false)

	assert.NoFileExists(t, changelogPath(repoDir, "hello-world", "1.0"))
	assert.FileExists(t, changelogPath(repoDir, "hello-world", "2.0"))
}

// stripDigestFields rewrites a published Packages indice the way an older
// aptify wrote it, without the fields a current build has to backfill. Every
// variant is rewritten from the same bytes, exactly as the pipeline publishes
// them.
func stripDigestFields(t *testing.T, repoDir, archDir string) {
	t.Helper()

	packages := decodePackages(t, filepath.Join(repoDir, filepath.FromSlash(archDir), "Packages"))
	require.NotEmpty(t, packages)

	for i := range packages {
		packages[i].MD5sum = ""
		packages[i].SHA1 = ""
		packages[i].DescriptionMD5 = ""
	}

	var body bytes.Buffer
	require.NoError(t, deb822.Marshal(&body, packages))

	fsys := repofs.NewOS(repoDir)
	for _, name := range []string{"Packages", "Packages.gz", "Packages.xz"} {
		_, err := writeIndiceFile(fsys, path.Join(archDir, name), body.Bytes())
		require.NoError(t, err)
	}
}

// TestBackfillHealsIncompleteStanzas pins the only route by which an existing
// repository gains the fields older builds did not publish: the ingest keeps
// the stanza it already has for an unchanged .deb, so the backfill is what
// fills them in, and the release is republished over the rewritten indice.
func TestBackfillHealsIncompleteStanzas(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(0, debPath(t, "hello-world_1.0_amd64.deb")))
	mustBuild(t, repoDir, confPath, false, false)

	stripDigestFields(t, repoDir, distName(testReleaseName, testComponentName, "binary-amd64"))

	inReleasePath := filepath.Join(repoDir, "dists", testReleaseName, "InRelease")
	before, err := os.ReadFile(inReleasePath)
	require.NoError(t, err)

	mustBuild(t, repoDir, confPath, false, false)

	verifyRepo(t, repoDir, testReleaseName)

	packages := packagesIn(t, repoDir, "amd64")
	require.Len(t, packages, 1)

	pkg := packages[0]

	sums, err := hashsum.File(os.DirFS(repoDir), pkg.Filename)
	require.NoError(t, err)

	assert.Equal(t, sums.MD5, pkg.MD5sum)
	assert.Equal(t, sums.SHA1, pkg.SHA1)
	assert.Equal(t, pkg.DescriptionMD5Sum(), pkg.DescriptionMD5)

	after, err := os.ReadFile(inReleasePath)
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "the release was not republished over the backfilled indice")
}

// TestBackfillWarnsOnMissingPoolFile pins the deliberate leniency: a
// repository whose pool file has gone still builds, and the stanza keeps the
// checksums it was published with rather than the build failing.
func TestBackfillWarnsOnMissingPoolFile(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(0, debPath(t, "hello-world_1.0_amd64.deb")))
	mustBuild(t, repoDir, confPath, false, false)

	stripDigestFields(t, repoDir, distName(testReleaseName, testComponentName, "binary-amd64"))

	published := packagesIn(t, repoDir, "amd64")
	require.Len(t, published, 1)
	require.NoError(t, os.Remove(filepath.Join(repoDir, filepath.FromSlash(published[0].Filename))))

	mustBuild(t, repoDir, confPath, false, false)

	verifyRepo(t, repoDir, testReleaseName)

	packages := packagesIn(t, repoDir, "amd64")
	require.Len(t, packages, 1)

	// Nothing to hash, so the checksums stay as they were published; the
	// description digest needs no pool file and is filled in anyway.
	assert.Empty(t, packages[0].MD5sum)
	assert.Empty(t, packages[0].SHA1)
	assert.NotEmpty(t, packages[0].DescriptionMD5)
}

// TestRereadKeepsRecordedFileFields pins what --reread does and what it must
// not do: the control metadata is taken from the pool again, while the
// Filename, Size and SHA256 the indice recorded are carried across, since the
// control file carries none of them. On an unchanged tree it republishes
// nothing at all.
func TestRereadKeepsRecordedFileFields(t *testing.T) {
	repoDir := t.TempDir()

	debFile := buildTestDeb(t, t.TempDir(), debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		description: "the published description",
		files:       map[string]string{"usr/bin/demo-tool": "one\n"},
	})

	confPath := writeTestConfig(t, singleComponentConfig(0, debFile))
	mustBuild(t, repoDir, confPath, false, false)

	before := snapshotTree(t, repoDir)

	mustBuild(t, repoDir, confPath, false, true)

	require.Equal(t, before, snapshotTree(t, repoDir),
		"rereading an unchanged tree republished something")

	recorded := packagesIn(t, repoDir, "amd64")
	require.Len(t, recorded, 1)

	// The same package rebuilt under the same version: apt would never notice,
	// but a reread picks the control data up.
	doctored := buildTestDeb(t, t.TempDir(), debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		description: "the rebuilt description",
		files: map[string]string{
			"usr/bin/demo-tool":        "two\n",
			"usr/share/demo/extra.txt": "extra\n",
		},
	})

	body, err := os.ReadFile(doctored)
	require.NoError(t, err)

	poolPath := filepath.Join(repoDir, filepath.FromSlash(recorded[0].Filename))
	require.NoError(t, os.WriteFile(poolPath, body, 0o644))

	mustBuild(t, repoDir, confPath, false, true)

	verifyRepo(t, repoDir, testReleaseName)

	packages := packagesIn(t, repoDir, "amd64")
	require.Len(t, packages, 1)

	assert.Equal(t, "the rebuilt description", packages[0].Description)

	assert.Equal(t, recorded[0].Filename, packages[0].Filename)
	assert.Equal(t, recorded[0].Size, packages[0].Size)
	assert.Equal(t, recorded[0].SHA256, packages[0].SHA256)

	// Deliberately the recorded values rather than the file's own: a rebuilt
	// package wants a version bump, the reread does not invent one.
	sums, err := hashsum.File(repofs.LocalFile(poolPath))
	require.NoError(t, err)
	assert.NotEqual(t, sums.SHA256, packages[0].SHA256)

	// Contents is read from the pool again as well, so the paths of the file
	// that is actually published are the ones described.
	assert.Contains(t,
		readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")),
		"usr/share/demo/extra.txt")
}

// TestForcedRebuildRepublishesNothing pins the compare before write: --force
// regenerates every indice, but an indice whose bytes are unchanged is not
// written, so the release is not republished and a mirror sees nothing.
func TestForcedRebuildRepublishesNothing(t *testing.T) {
	repoDir := t.TempDir()
	confPath := writeTestConfig(t, demoConfig(t))

	mustBuild(t, repoDir, confPath, false, false)
	before := snapshotTree(t, repoDir)

	mustBuild(t, repoDir, confPath, true, false)

	assert.Equal(t, before, snapshotTree(t, repoDir))
}

// TestInspectListsPublishedPackages pins the inspect output: JSON of every
// package the repository publishes, each one once, even though an
// architecture `all` package is folded into every architecture's indice.
func TestInspectListsPublishedPackages(t *testing.T) {
	repoDir := t.TempDir()

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_1.0_arm64.deb"),
		debPath(t, "hello-world_3.0_all.deb"),
	)), false, false)

	// Published in both architectures' indices, so a naive concatenation would
	// list it twice.
	require.Contains(t, packageVersions(packagesIn(t, repoDir, "amd64")), "hello-world 3.0 all")
	require.Contains(t, packageVersions(packagesIn(t, repoDir, "arm64")), "hello-world 3.0 all")

	var buf bytes.Buffer
	require.NoError(t, Inspect(repofs.NewOS(repoDir), &buf))

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
