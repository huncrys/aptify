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
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/types"
)

// writeReleaseTree fills a release directory with the files below, each
// holding its own name, and returns the repository it lives in.
func writeReleaseTree(t *testing.T, names ...string) (repofs.FS, string) {
	t.Helper()

	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	for _, name := range names {
		full := path.Join("dists/bookworm", name)

		require.NoError(t, fsys.MkdirAll(path.Dir(full)))
		require.NoError(t, os.WriteFile(filepath.Join(dir, filepath.FromSlash(full)), []byte(name), 0o644))
	}

	return fsys, "dists/bookworm"
}

// TestReleaseIndiceNames covers which files a release publishes checksums for.
// The exclusions are the load bearing part: a by-hash entry serves a file
// listed under its own name, and a temporary belongs to a build that has not
// published anything yet.
func TestReleaseIndiceNames(t *testing.T) {
	fsys, releaseDir := writeReleaseTree(t,
		// Listed.
		"main/binary-amd64/Packages",
		"main/binary-amd64/Packages.gz",
		"main/binary-amd64/Packages.xz",
		"main/binary-amd64/Release",
		"main/Contents-amd64",
		"main/Contents-amd64.gz",
		// Not listed.
		"Release",
		"Release.gpg",
		"InRelease",
		"main/binary-amd64/.Packages.12345",
		"main/binary-amd64/by-hash/SHA256/cafebabe",
		"main/by-hash/SHA256/deadbeef",
		"main/binary-amd64/Release.gpg",
	)

	names, err := releaseIndiceNames(fsys, releaseDir)
	require.NoError(t, err)

	// The order is the one the Release file lists them in, and it is the order
	// a directory walk produced before the list was globbed: an existing
	// repository must not be republished just to reshuffle its stanza.
	assert.Equal(t, []string{
		"main/Contents-amd64",
		"main/Contents-amd64.gz",
		"main/binary-amd64/Packages",
		"main/binary-amd64/Packages.gz",
		"main/binary-amd64/Packages.xz",
		"main/binary-amd64/Release",
	}, names)
}

// TestReleaseSumsSources pins where each checksum comes from: what this build
// published, else what the release being replaced recorded, else a read of the
// file itself.
func TestReleaseSumsSources(t *testing.T) {
	const (
		published = "main/binary-amd64/Packages"
		carried   = "main/binary-amd64/Packages.gz"
		unknown   = "main/binary-amd64/Release"
	)

	fsys, releaseDir := writeReleaseTree(t, published, carried, unknown)

	// Deliberately not the checksums of the files on disk, so that the source
	// of each entry is visible in the result.
	publishedSums := map[string]hashsum.Sums{
		published: {Path: published, Size: 1, MD5: "pmd5", SHA1: "psha1", SHA256: "psha256"},
	}

	recorded := []hashsum.Sums{
		{Path: published, Size: 2, MD5: "smd5", SHA1: "ssha1", SHA256: "ssha256"},
		{Path: carried, Size: 3, MD5: "cmd5", SHA1: "csha1", SHA256: "csha256"},
	}

	existing := &types.Release{
		MD5Sum: hashsum.MD5List(recorded),
		SHA1:   hashsum.SHA1List(recorded),
		SHA256: hashsum.SHA256List(recorded),
	}

	sums, err := releaseSums(fsys, releaseDir, publishedSums, existing, false)
	require.NoError(t, err)

	read, err := hashsum.File(fsys, path.Join(releaseDir, unknown))
	require.NoError(t, err)
	read.Path = unknown

	assert.Equal(t, []hashsum.Sums{
		// This build's own checksums outrank the ones the old release
		// recorded for the same file.
		publishedSums[published],
		// Untouched by this build, so its entry is carried across rather
		// than the file being read again.
		{Path: carried, Size: 3, MD5: "cmd5", SHA1: "csha1", SHA256: "csha256"},
		// Named by neither, which is how a file the old release never
		// listed gets into the new one.
		read,
	}, sums)
}

// TestReleaseSumsForceRehashes pins the escape hatch: --force ignores every
// recorded checksum and describes what is actually on the storage.
func TestReleaseSumsForceRehashes(t *testing.T) {
	const name = "main/binary-amd64/Packages"

	fsys, releaseDir := writeReleaseTree(t, name)

	wrong := hashsum.Sums{Path: name, Size: 1, MD5: "md5", SHA1: "sha1", SHA256: "sha256"}

	recorded := []hashsum.Sums{wrong}
	existing := &types.Release{
		MD5Sum: hashsum.MD5List(recorded),
		SHA1:   hashsum.SHA1List(recorded),
		SHA256: hashsum.SHA256List(recorded),
	}

	sums, err := releaseSums(fsys, releaseDir,
		map[string]hashsum.Sums{name: wrong}, existing, true)
	require.NoError(t, err)

	want, err := hashsum.File(fsys, path.Join(releaseDir, name))
	require.NoError(t, err)
	want.Path = name

	assert.Equal(t, []hashsum.Sums{want}, sums)
}

// TestReleaseSumsIgnoreIncompleteRecords covers the repository an older aptify
// published: a release listing SHA256 alone cannot supply the other two
// algorithms, so the file is read rather than half described.
func TestReleaseSumsIgnoreIncompleteRecords(t *testing.T) {
	const name = "main/binary-amd64/Packages"

	fsys, releaseDir := writeReleaseTree(t, name)

	existing := &types.Release{
		SHA256: hashsum.SHA256List([]hashsum.Sums{{Path: name, Size: 1, SHA256: "sha256"}}),
	}

	sums, err := releaseSums(fsys, releaseDir, nil, existing, false)
	require.NoError(t, err)

	want, err := hashsum.File(fsys, path.Join(releaseDir, name))
	require.NoError(t, err)
	want.Path = name

	assert.Equal(t, []hashsum.Sums{want}, sums)
}

// TestReleaseSumsWithoutAnExistingRelease covers the first build of a
// repository: there is nothing to carry across, and every file this build did
// not publish is read.
func TestReleaseSumsWithoutAnExistingRelease(t *testing.T) {
	const name = "main/Contents-amd64"

	fsys, releaseDir := writeReleaseTree(t, name)

	sums, err := releaseSums(fsys, releaseDir, nil, nil, false)
	require.NoError(t, err)

	want, err := hashsum.File(fsys, path.Join(releaseDir, name))
	require.NoError(t, err)
	want.Path = name

	assert.Equal(t, []hashsum.Sums{want}, sums)
}

// TestReleaseCarriesUntouchedComponents drives the carrying across end to end:
// a release with two components where only one changed is republished over
// indices the build never opened, and it still describes them correctly.
func TestReleaseCarriesUntouchedComponents(t *testing.T) {
	repoDir := t.TempDir()

	untouched := componentConfig("extra", 0, debPath(t, "hello-world_1.0_arm64.deb"))

	mustBuild(t, repoDir, writeTestConfig(t, testConfig(releaseConfig(testReleaseName,
		componentConfig(testComponentName, 0, debPath(t, "hello-world_1.0_amd64.deb")),
		untouched))), false, false)

	packagesPath := distPath(repoDir, testReleaseName, "extra", "binary-arm64", "Packages")
	before := fileMTime(t, packagesPath)

	mustBuild(t, repoDir, writeTestConfig(t, testConfig(releaseConfig(testReleaseName,
		componentConfig(testComponentName, 0,
			debPath(t, "hello-world_1.0_amd64.deb"),
			debPath(t, "hello-world_2.0_amd64.deb")),
		untouched))), false, false)

	// Every checksum the release publishes is checked against the file it
	// names, the untouched component's included.
	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, before, fileMTime(t, packagesPath),
		"the untouched component's indice was republished")

	release := readSignedRelease(t, repoDir)

	var listed []string
	for _, entry := range release.SHA256 {
		listed = append(listed, entry.Filename)
	}
	assert.Contains(t, listed, "extra/binary-arm64/Packages")
}

// TestReleaseSumsDropVanishedFiles pins that the list describes the storage
// rather than the old release: an indice the build removed is not listed just
// because the release being replaced named it.
func TestReleaseSumsDropVanishedFiles(t *testing.T) {
	const name = "main/binary-amd64/Packages"

	fsys, releaseDir := writeReleaseTree(t, name)

	recorded := []hashsum.Sums{
		{Path: name, Size: int64(len(name)), MD5: "md5", SHA1: "sha1", SHA256: "sha256"},
		{Path: "main/binary-all/Packages", Size: 1, MD5: "md5", SHA1: "sha1", SHA256: "sha256"},
	}

	existing := &types.Release{
		MD5Sum: hashsum.MD5List(recorded),
		SHA1:   hashsum.SHA1List(recorded),
		SHA256: hashsum.SHA256List(recorded),
	}

	sums, err := releaseSums(fsys, releaseDir, nil, existing, false)
	require.NoError(t, err)

	require.Len(t, sums, 1)
	assert.Equal(t, name, sums[0].Path)
}
