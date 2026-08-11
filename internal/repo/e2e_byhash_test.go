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
	"path"
	"path/filepath"
	"testing"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/filehash"
	"oaklab.hu/debian/deb822/types/list"
)

// byHashConfig is the configuration of the by-hash tests: one component over
// the given packages, with by-hash publishing turned on.
func byHashConfig(packages ...string) *v1alpha1.Repository {
	conf := singleComponentConfig(0, packages...)
	conf.ByHash.Enabled = true

	return conf
}

// readSignedRelease decodes the live release of the test release, verifying it
// against the signing key.
func readSignedRelease(t *testing.T, repoDir string) types.Release {
	t.Helper()

	return decodeRelease(t, filepath.Join(repoDir, "dists", testReleaseName, "InRelease"),
		openpgp.EntityList{testEntity(t)})
}

// byHashEntry is where the by-hash entry of an index named by a release lives.
func byHashEntry(t *testing.T, repoDir, algorithm, indice string, hashes list.NewLineDelimited[filehash.FileHash]) string {
	t.Helper()

	for _, hash := range hashes {
		if hash.Filename == indice {
			return filepath.Join(repoDir, "dists", testReleaseName,
				filepath.FromSlash(path.Dir(indice)), "by-hash", algorithm, hash.Hash)
		}
	}

	t.Fatalf("the release does not name %s", indice)

	return ""
}

// byHashDirectories lists every by-hash tree published below a release.
func byHashDirectories(t *testing.T, repoDir string) []string {
	t.Helper()

	var dirs []string

	require.NoError(t, filepath.WalkDir(filepath.Join(repoDir, "dists"),
		func(dirPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() && d.Name() == "by-hash" {
				dirs = append(dirs, dirPath)
			}

			return nil
		}))

	return dirs
}

// assertServesIndice checks that the by-hash entry serves the index's bytes,
// and reports whether it is that very file rather than a copy of it. An entry
// is named after its content, so two indices holding the same bytes share a
// single entry and only one of them can be the file it links to.
func assertServesIndice(t *testing.T, indicePath, entryPath string) bool {
	t.Helper()

	indice, err := os.Stat(indicePath)
	require.NoError(t, err)

	entry, err := os.Stat(entryPath)
	require.NoError(t, err, "no by-hash entry for %s", indicePath)

	published, err := os.ReadFile(indicePath)
	require.NoError(t, err)

	served, err := os.ReadFile(entryPath)
	require.NoError(t, err)

	assert.Equal(t, published, served, "%s does not serve the content of %s", entryPath, indicePath)

	return os.SameFile(indice, entry)
}

// TestByHashPublishesEveryListedIndice pins what a client holding a release
// may ask for: every index the release names is published under each of its
// checksums as well, as a link to the index itself, and both the release and
// the per architecture stubs advertise it.
func TestByHashPublishesEveryListedIndice(t *testing.T) {
	repoDir := t.TempDir()

	mustBuild(t, repoDir, writeTestConfig(t, byHashConfig(
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_1.0_arm64.deb"),
	)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	releaseDir := filepath.Join(repoDir, "dists", testReleaseName)
	release := readSignedRelease(t, repoDir)

	require.NotNil(t, release.AcquireByHash)
	assert.True(t, bool(*release.AcquireByHash))

	// The indices each entry has to serve. Two indices with identical bytes -
	// the Contents of two architectures shipping the same paths, here - are
	// named by one entry, so they are checked together.
	indicesForEntry := make(map[string][]string)

	for algorithm, hashes := range map[string]list.NewLineDelimited[filehash.FileHash]{
		"MD5Sum": release.MD5Sum,
		"SHA1":   release.SHA1,
		"SHA256": release.SHA256,
	} {
		require.NotEmpty(t, hashes, "the release publishes no %s list", algorithm)

		for _, hash := range hashes {
			entryPath := filepath.Join(releaseDir, filepath.FromSlash(path.Dir(hash.Filename)),
				"by-hash", algorithm, hash.Hash)

			indicesForEntry[entryPath] = append(indicesForEntry[entryPath],
				filepath.Join(releaseDir, filepath.FromSlash(hash.Filename)))
		}
	}

	for entryPath, indices := range indicesForEntry {
		var linked bool
		for _, indicePath := range indices {
			linked = assertServesIndice(t, indicePath, entryPath) || linked
		}

		assert.True(t, linked, "%s is a copy rather than a link to one of %v", entryPath, indices)
	}

	// Contents is a component level indice, so its entries live in the
	// component's by-hash tree rather than an architecture's.
	assertServesIndice(t,
		distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64"),
		byHashEntry(t, repoDir, "SHA256", testComponentName+"/Contents-amd64", release.SHA256))

	for _, architecture := range []string{"amd64", "arm64"} {
		stubPath := distPath(repoDir, testReleaseName, testComponentName, "binary-"+architecture, "Release")

		assert.Contains(t, stanzaFields(t, stubPath), "Acquire-By-Hash")

		stub := decodeComponentRelease(t, stubPath)
		require.NotNil(t, stub.AcquireByHash)
		assert.True(t, bool(*stub.AcquireByHash))
	}
}

// TestByHashKeepsSupersededIndice pins why the tree exists at all: a client
// that read the previous release must still be able to fetch the index it
// names after a later build replaced it. The superseded entry survives, and
// its retention window only starts as it leaves the release.
func TestByHashKeepsSupersededIndice(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, byHashConfig(older)), false, false)

	const indice = testComponentName + "/binary-amd64/Packages"

	supersededPath := byHashEntry(t, repoDir, "SHA256", indice, readSignedRelease(t, repoDir).SHA256)
	supersededBefore := fileMTime(t, supersededPath)

	mustBuild(t, repoDir, writeTestConfig(t, byHashConfig(older, newer)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	currentPath := byHashEntry(t, repoDir, "SHA256", indice, readSignedRelease(t, repoDir).SHA256)
	require.NotEqual(t, supersededPath, currentPath, "the indice was not replaced")

	assert.FileExists(t, supersededPath,
		"the superseded entry was deleted the moment it stopped being current")
	assert.True(t, fileMTime(t, supersededPath).After(supersededBefore),
		"the superseded entry was not touched, so its retention window never started")

	assert.True(t, assertServesIndice(t,
		distPath(repoDir, testReleaseName, testComponentName, "binary-amd64", "Packages"), currentPath),
		"the replacement indice was not linked into the by-hash tree")
}

// TestByHashPrunesExpiredEntries pins the sweep: an entry is deleted once it
// has been out of the release for the retention window, and an entry the live
// release still names is kept however old its content is.
func TestByHashPrunesExpiredEntries(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, byHashConfig(older)), false, false)

	const indice = testComponentName + "/binary-amd64/Packages"

	supersededPath := byHashEntry(t, repoDir, "SHA256", indice, readSignedRelease(t, repoDir).SHA256)

	conf := writeTestConfig(t, byHashConfig(older, newer))
	mustBuild(t, repoDir, conf, false, false)

	currentPath := byHashEntry(t, repoDir, "SHA256", indice, readSignedRelease(t, repoDir).SHA256)

	// Both are older than the seven day default: the one the release still
	// names is current whatever its mtime says, the other has waited out its
	// window.
	expired := stdtime.Now().Add(-8 * 24 * stdtime.Hour)
	for _, entryPath := range []string{supersededPath, currentPath} {
		require.NoError(t, os.Chtimes(entryPath, stdtime.Time{}, expired))
	}

	mustBuild(t, repoDir, conf, false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.NoFileExists(t, supersededPath, "the expired entry was kept")
	assert.FileExists(t, currentPath, "an entry the live release names was swept")
}

// TestByHashDisabledRemovesTrees pins the order turning the feature off has to
// follow: the release stops advertising by-hash, and only then is the tree it
// described deleted.
func TestByHashDisabledRemovesTrees(t *testing.T) {
	repoDir := t.TempDir()
	older, _ := versionedFixtures(t)

	mustBuild(t, repoDir, writeTestConfig(t, byHashConfig(older)), false, false)
	require.NotEmpty(t, byHashDirectories(t, repoDir))

	mustBuild(t, repoDir, writeTestConfig(t, singleComponentConfig(0, older)), false, false)

	verifyRepo(t, repoDir, testReleaseName)

	assert.Empty(t, byHashDirectories(t, repoDir), "by-hash trees outlived the flag")

	assert.Nil(t, readSignedRelease(t, repoDir).AcquireByHash)
	assert.NotContains(t, stanzaFields(t, filepath.Join(repoDir, "dists", testReleaseName, "Release")),
		"Acquire-By-Hash")
	assert.NotContains(t,
		stanzaFields(t, distPath(repoDir, testReleaseName, testComponentName, "binary-amd64", "Release")),
		"Acquire-By-Hash")
}
