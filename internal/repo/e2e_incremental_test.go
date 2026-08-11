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
	"os"
	"path/filepath"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/deb822/types"
)

// versionedFixtures builds two versions of one package whose published
// contents differ, which the checked in packages do not: hello-world ships the
// same paths in every version, so nothing about them can tell which version an
// indice describes.
func versionedFixtures(t *testing.T) (older, newer string) {
	t.Helper()

	dir := t.TempDir()

	older = buildTestDeb(t, dir, debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		description: "the older version",
		files: map[string]string{
			"usr/bin/demo-tool":      "one\n",
			"usr/share/demo/one.txt": "one\n",
		},
	})

	newer = buildTestDeb(t, dir, debFixture{
		name: "demo-tool", version: "2.0", architecture: "amd64",
		description: "the newer version",
		files: map[string]string{
			"usr/bin/demo-tool":      "two\n",
			"usr/share/demo/two.txt": "two\n",
		},
	})

	return older, newer
}

// TestBuildAddsNewerVersion pins the ordinary incremental update: the stanza
// joins the Packages indice, and because Contents has no version column and
// describes the version a client would install, it is re-read from the new
// winner. The release names new checksums, so it is republished.
func TestBuildAddsNewerVersion(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, older)), false, false)

	contentsPath := distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")
	require.Contains(t, readContents(t, contentsPath), "usr/share/demo/one.txt")

	inReleasePath := filepath.Join(repoDir, "dists", testReleaseName, "InRelease")
	before, err := os.ReadFile(inReleasePath)
	require.NoError(t, err)

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, older, newer)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"demo-tool 1.0 amd64", "demo-tool 2.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	// The newest version is the one a client installs, so it is the one
	// Contents describes - the older version's paths are gone.
	published := readContents(t, contentsPath)
	assert.Contains(t, published, "usr/share/demo/two.txt")
	assert.NotContains(t, published, "usr/share/demo/one.txt")

	after, err := os.ReadFile(inReleasePath)
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "the release was not republished over changed indices")
}

// TestBuildAddsOlderVersion pins the half of the winner comparison that a
// "which packages did this build touch" rule gets wrong: an older version is
// published in Packages, but it is not what a client would install, so
// Contents must not change - not its bytes and not its modification time.
func TestBuildAddsOlderVersion(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, newer)), false, false)

	type publishedIndice struct {
		body  []byte
		mtime stdtime.Time
	}

	indices := map[string]publishedIndice{}
	for _, name := range []string{"Contents-amd64", "Contents-amd64.gz"} {
		indicePath := distPath(repoDir, testReleaseName, testComponentName, name)

		body, err := os.ReadFile(indicePath)
		require.NoError(t, err)

		indices[name] = publishedIndice{body: body, mtime: fileMTime(t, indicePath)}
	}

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, older, newer)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"demo-tool 1.0 amd64", "demo-tool 2.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	for name, before := range indices {
		indicePath := distPath(repoDir, testReleaseName, testComponentName, name)

		body, err := os.ReadFile(indicePath)
		require.NoError(t, err)

		assert.Equal(t, before.body, body, "%s changed over an added older version", name)
		assert.Equal(t, before.mtime, fileMTime(t, indicePath),
			"%s was rewritten with identical bytes", name)
	}
}

// TestBuildPrunesSurplusVersions pins max_versions and the pool garbage
// collection it feeds: the surplus stanza and its pool file go, the version a
// client installs stays - file and all - and Contents still describes it.
func TestBuildPrunesSurplusVersions(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, older, newer)), false, false)

	poolDir := filepath.Join(repoDir, "pool", testComponentName, "d", "demo-tool")
	require.FileExists(t, filepath.Join(poolDir, "demo-tool_1.0_amd64.deb"))

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(1, older, newer)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"demo-tool 2.0 amd64"}, packageVersions(packagesIn(t, repoDir, "amd64")))

	// The pool is collected from the final package lists, so the surplus file
	// goes and the one still listed survives.
	assert.NoFileExists(t, filepath.Join(poolDir, "demo-tool_1.0_amd64.deb"))
	assert.FileExists(t, filepath.Join(poolDir, "demo-tool_2.0_amd64.deb"))

	// max_versions only ever drops versions that already lost to the winner, so
	// the version Contents describes is the one it described before.
	published := readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64"))
	assert.Contains(t, published, "usr/share/demo/two.txt")
	assert.NotContains(t, published, "usr/share/demo/one.txt")
}

// TestBuildPruneDropsFoldedArchAllPackage pins the other side of the fold: an
// architecture `all` package competes with every architecture's own versions,
// so one architecture's newer version can make it surplus everywhere it is
// judged - and it then disappears from the indices of an architecture that was
// publishing nothing else of it, Contents included.
func TestBuildPruneDropsFoldedArchAllPackage(t *testing.T) {
	repoDir := t.TempDir()
	dir := t.TempDir()

	// Keeps amd64 an architecture of the component once the `all` package is
	// gone from it.
	keeper := buildTestDeb(t, dir, debFixture{
		name: "demo-keeper", version: "1.0", architecture: "amd64",
		files: map[string]string{"usr/bin/demo-keeper": "keep\n"},
	})

	sharedAll := buildTestDeb(t, dir, debFixture{
		name: "demo-shared", version: "1.0", architecture: "all",
		files: map[string]string{"usr/share/demo-shared/any.txt": "any\n"},
	})

	sharedArm := buildTestDeb(t, dir, debFixture{
		name: "demo-shared", version: "2.0", architecture: "arm64",
		files: map[string]string{"usr/lib/demo-shared/arm64.so": "arm\n"},
	})

	packages := []string{keeper, sharedAll, sharedArm}

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, packages...)), false, false)

	// Folded in: amd64 publishes the `all` package even though it has no
	// version of its own.
	assert.Equal(t, []string{"demo-keeper 1.0 amd64", "demo-shared 1.0 all"},
		packageVersions(packagesIn(t, repoDir, "amd64")))
	assert.Contains(t,
		readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")),
		"usr/share/demo-shared/any.txt")

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(1, packages...)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	// arm64 is the only architecture judging demo-shared, and there its own 2.0
	// outranks the `all` 1.0, so the single shared entry is dropped.
	assert.Equal(t, []string{"demo-keeper 1.0 amd64"}, packageVersions(packagesIn(t, repoDir, "amd64")))
	assert.Equal(t, []string{"demo-shared 2.0 arm64"}, packageVersions(packagesIn(t, repoDir, "arm64")))

	assert.NotContains(t,
		readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")),
		"usr/share/demo-shared/any.txt",
		"Contents still describes a package the architecture no longer publishes")

	assert.NoFileExists(t,
		filepath.Join(repoDir, "pool", testComponentName, "d", "demo-shared", "demo-shared_1.0_all.deb"))
}

// TestBuildMigratesArchAllIndices pins the migration off the layout older
// versions published: once a component has an architecture to fold `all` into,
// binary-all and Contents-all* are deleted and everything they held is
// published inside the real architecture's indices instead.
func TestBuildMigratesArchAllIndices(t *testing.T) {
	repoDir := t.TempDir()
	dir := t.TempDir()

	allDeb := buildTestDeb(t, dir, debFixture{
		name: "demo-any", version: "1.0", architecture: "all",
		files: map[string]string{"usr/share/demo-any/data.txt": "any\n"},
	})

	amd64Deb := buildTestDeb(t, dir, debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		files: map[string]string{"usr/bin/demo-tool": "tool\n"},
	})

	// A component with nothing to fold `all` into publishes it as an
	// architecture of its own, which is the tree the migration has to clean up.
	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, allDeb)), false, false)

	binaryAllDir := distPath(repoDir, testReleaseName, testComponentName, "binary-all")
	require.FileExists(t, filepath.Join(binaryAllDir, "Packages"))
	require.FileExists(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-all"))

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, allDeb, amd64Deb)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.NoDirExists(t, binaryAllDir)
	for _, name := range []string{"Contents-all", "Contents-all.gz"} {
		assert.NoFileExists(t, distPath(repoDir, testReleaseName, testComponentName, name))
	}

	// Nothing the dropped indices held is lost: the `all` package is published
	// inside amd64's indices, Contents included.
	assert.Equal(t, []string{"demo-any 1.0 all", "demo-tool 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	published := readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64"))
	assert.Contains(t, published, "usr/share/demo-any/data.txt")
	assert.Contains(t, published, "usr/bin/demo-tool")

	release := decodeRelease(t, filepath.Join(repoDir, "dists", testReleaseName, "Release"), nil)
	assert.Equal(t, []string{"amd64"}, architectureNames(release))
}

// TestBuildKeepsArchAllWithoutOtherArchitectures pins the exception and the
// Release field that has to follow it: a component with nothing to fold `all`
// into keeps publishing binary-all, and its release must not tell apt to ignore
// indices the release itself lists.
func TestBuildKeepsArchAllWithoutOtherArchitectures(t *testing.T) {
	repoDir := t.TempDir()
	dir := t.TempDir()

	allDeb := buildTestDeb(t, dir, debFixture{
		name: "demo-any", version: "1.0", architecture: "all",
		files: map[string]string{"usr/share/demo-any/data.txt": "any\n"},
	})

	amd64Deb := buildTestDeb(t, dir, debFixture{
		name: "demo-tool", version: "1.0", architecture: "amd64",
		files: map[string]string{"usr/bin/demo-tool": "tool\n"},
	})

	confPath := writeTestConfig(t, testConfig(
		releaseConfig("bookworm-all", componentConfig(testComponentName, 0, allDeb)),
		releaseConfig("bookworm-mixed", componentConfig(testComponentName, 0, allDeb, amd64Deb)),
	))

	mustBuild(t, repoDir, confPath, false, false)

	verifyRepo(t, repoDir, "bookworm-all", "bookworm-mixed")

	for _, tc := range []struct {
		release                     string
		architectures               []string
		binaryAll                   bool
		noSupportForArchitectureAll string
	}{
		{
			release:       "bookworm-all",
			architectures: []string{"all"},
			binaryAll:     true,
		},
		{
			release:                     "bookworm-mixed",
			architectures:               []string{"amd64"},
			noSupportForArchitectureAll: "Packages",
		},
	} {
		t.Run(tc.release, func(t *testing.T) {
			binaryAllDir := distPath(repoDir, tc.release, testComponentName, "binary-all")
			if tc.binaryAll {
				assert.FileExists(t, filepath.Join(binaryAllDir, "Packages"))
				assert.FileExists(t, distPath(repoDir, tc.release, testComponentName, "Contents-all"))
			} else {
				assert.NoDirExists(t, binaryAllDir)
				assert.NoFileExists(t, distPath(repoDir, tc.release, testComponentName, "Contents-all"))
			}

			releasePath := filepath.Join(repoDir, "dists", tc.release, "Release")

			release := decodeRelease(t, releasePath, nil)
			assert.Equal(t, tc.architectures, architectureNames(release))
			assert.Equal(t, tc.noSupportForArchitectureAll, release.NoSupportForArchitectureAll)

			if tc.noSupportForArchitectureAll == "" {
				assert.NotContains(t, stanzaFields(t, releasePath), "No-Support-for-Architecture-all")
			}
		})
	}
}

// architectureNames is the Architectures field of a release as plain strings.
func architectureNames(release types.Release) []string {
	names := make([]string, 0, len(release.Architectures))
	for _, architecture := range release.Architectures {
		names = append(names, architecture.String())
	}

	return names
}
