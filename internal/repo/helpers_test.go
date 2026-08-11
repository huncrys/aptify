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
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/dpeckett/uncompr"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/keys"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
)

// testdataDir is the repository's testdata directory, relative to the package
// the tests run in.
const testdataDir = "../../testdata"

var (
	testEntityOnce sync.Once
	testEntityKey  *openpgp.Entity
	testEntityErr  error
)

// testKeyPath is the absolute path of the checked in signing key the end to end
// builds are signed with. It is a fixture, not a secret.
func testKeyPath(t *testing.T) string {
	t.Helper()

	keyPath, err := filepath.Abs(filepath.Join(testdataDir, "keys", "test_private.asc"))
	require.NoError(t, err)
	require.FileExists(t, keyPath)

	return keyPath
}

// testEntity loads the fixture key, once per test binary: reading it is pure
// parsing, so every test can share the entity.
func testEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	keyPath := testKeyPath(t)

	testEntityOnce.Do(func() {
		testEntityKey, testEntityErr = keys.Load(keyPath)
	})

	require.NoError(t, testEntityErr)
	require.NotNil(t, testEntityKey)

	return testEntityKey
}

// debPath is the absolute path of one of the checked in test packages.
func debPath(t *testing.T, name string) string {
	t.Helper()

	pkgPath, err := filepath.Abs(filepath.Join(testdataDir, "package", name))
	require.NoError(t, err)
	require.FileExists(t, pkgPath)

	return pkgPath
}

// writeTestConfig renders the configuration to a file the build can be pointed
// at. Package globs are resolved against the process working directory, so
// callers have to spell them absolutely.
func writeTestConfig(t *testing.T, conf *v1alpha1.Repository) string {
	t.Helper()

	confPath := filepath.Join(t.TempDir(), "aptify.yaml")

	confFile, err := os.Create(confPath)
	require.NoError(t, err)

	require.NoError(t, config.ToYAML(confFile, conf))
	require.NoError(t, confFile.Close())

	return confPath
}

// mustBuild runs a full build of the repository, in process.
func mustBuild(t *testing.T, repoDir, confPath string, force, reread bool) {
	t.Helper()

	require.NoError(t, Build(Options{
		RepoDir:        repoDir,
		ConfigPath:     confPath,
		PrivateKeyPath: testKeyPath(t),
		Force:          force,
		Reread:         reread,
	}))
}

// treeEntry is what a published file is compared by across builds: its bytes
// and the modification time a mirror sees.
type treeEntry struct {
	sha256 string
	mtime  stdtime.Time
}

// snapshotTree records every file below dir, keyed by its slash separated path
// relative to dir.
func snapshotTree(t *testing.T, dir string) map[string]treeEntry {
	t.Helper()

	tree := make(map[string]treeEntry)

	require.NoError(t, filepath.WalkDir(dir, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(dir, filePath)
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		sums, err := hashsum.File(filePath)
		if err != nil {
			return err
		}

		tree[filepath.ToSlash(relativePath)] = treeEntry{sha256: sums.SHA256, mtime: fi.ModTime()}

		return nil
	}))

	return tree
}

// verifyRepo checks that each release is one an apt client could actually use:
// the signatures verify against the signing key, every file the release names
// is on disk with the size and checksums it publishes, every index is published
// in all of its variants with the same content behind each, and the signed and
// unsigned copies of the release agree.
func verifyRepo(t *testing.T, repoDir string, releases ...string) {
	t.Helper()

	for _, release := range releases {
		releaseDir := filepath.Join(repoDir, "dists", release)

		// The keyring is what makes this a verification rather than a read: a
		// release signed by anything else fails to decode.
		signed := decodeRelease(t, filepath.Join(releaseDir, "InRelease"), openpgp.EntityList{testEntity(t)})

		// Release carries the same stanza without the clearsigning, and
		// Release.gpg signs exactly those bytes.
		plain := decodeRelease(t, filepath.Join(releaseDir, "Release"), nil)
		require.Equal(t, plain, signed, "Release and InRelease disagree in %s", release)

		verifyDetachedSignature(t, releaseDir)

		require.NotEmpty(t, signed.SHA256, "%s publishes no checksums", release)
		require.NotEmpty(t, signed.Components)
		require.NotEmpty(t, signed.Architectures)

		// Every file the release names, hashed once and checked against all
		// three lists.
		sumsByName := make(map[string]hashsum.Sums, len(signed.SHA256))
		for _, entry := range signed.SHA256 {
			filePath := filepath.Join(releaseDir, filepath.FromSlash(entry.Filename))
			require.FileExists(t, filePath, "%s names a file that is not published", release)

			sums, err := hashsum.File(filePath)
			require.NoError(t, err)

			require.Equal(t, entry.Size, sums.Size, "%s: size of %s", release, entry.Filename)
			require.Equal(t, entry.Hash, sums.SHA256, "%s: SHA256 of %s", release, entry.Filename)

			sumsByName[entry.Filename] = sums
		}

		require.Len(t, signed.MD5Sum, len(signed.SHA256), "%s: MD5Sum lists a different set of files", release)
		for _, entry := range signed.MD5Sum {
			sums, ok := sumsByName[entry.Filename]
			require.True(t, ok, "%s: MD5Sum names %s, SHA256 does not", release, entry.Filename)
			require.Equal(t, entry.Hash, sums.MD5, "%s: MD5Sum of %s", release, entry.Filename)
			require.Equal(t, entry.Size, sums.Size)
		}

		require.Len(t, signed.SHA1, len(signed.SHA256), "%s: SHA1 lists a different set of files", release)
		for _, entry := range signed.SHA1 {
			sums, ok := sumsByName[entry.Filename]
			require.True(t, ok, "%s: SHA1 names %s, SHA256 does not", release, entry.Filename)
			require.Equal(t, entry.Hash, sums.SHA1, "%s: SHA1 of %s", release, entry.Filename)
			require.Equal(t, entry.Size, sums.Size)
		}

		verifyIndiceVariants(t, releaseDir, release, sumsByName)
	}
}

// verifyIndiceVariants checks that every index is listed under its
// uncompressed name as well as its compressed ones - apt resolves a target by
// the uncompressed key and only then picks a variant to fetch - and that all of
// them decompress to the same bytes.
func verifyIndiceVariants(t *testing.T, releaseDir, release string, listed map[string]hashsum.Sums) {
	t.Helper()

	for name := range listed {
		base := path.Base(name)

		switch {
		case strings.HasSuffix(name, ".gz"), strings.HasSuffix(name, ".xz"):
			uncompressed := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".xz")
			require.Contains(t, listed, uncompressed,
				"%s: %s is published without its uncompressed variant", release, name)

			want, err := os.ReadFile(filepath.Join(releaseDir, filepath.FromSlash(uncompressed)))
			require.NoError(t, err)

			require.Equal(t, want, decompress(t, filepath.Join(releaseDir, filepath.FromSlash(name))),
				"%s: %s does not hold the same content as %s", release, name, uncompressed)
		case base == "Packages":
			require.Contains(t, listed, name+".gz", "%s: %s has no gzip variant", release, name)
			require.Contains(t, listed, name+".xz", "%s: %s has no xz variant", release, name)
		case strings.HasPrefix(base, "Contents-"):
			require.Contains(t, listed, name+".gz", "%s: %s has no gzip variant", release, name)
		}
	}
}

// decodeRelease reads a release stanza, verifying the signature against the
// keyring when one is given.
func decodeRelease(t *testing.T, releasePath string, keyring openpgp.EntityList) types.Release {
	t.Helper()

	releaseFile, err := os.Open(releasePath)
	require.NoError(t, err)
	defer releaseFile.Close()

	decoder, err := deb822.NewDecoder(releaseFile, keyring)
	require.NoError(t, err)

	if keyring != nil {
		require.NotNil(t, decoder.Signer(), "%s is not signed by the repository key", releasePath)
	}

	var release types.Release
	require.NoError(t, decoder.Decode(&release))

	return release
}

// verifyDetachedSignature checks Release.gpg against Release.
func verifyDetachedSignature(t *testing.T, releaseDir string) {
	t.Helper()

	body, err := os.Open(filepath.Join(releaseDir, "Release"))
	require.NoError(t, err)
	defer body.Close()

	signature, err := os.Open(filepath.Join(releaseDir, "Release.gpg"))
	require.NoError(t, err)
	defer signature.Close()

	signer, err := openpgp.CheckArmoredDetachedSignature(
		openpgp.EntityList{testEntity(t)}, body, signature, nil)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

// decompress returns the content of a compressed index.
func decompress(t *testing.T, filePath string) []byte {
	t.Helper()

	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	r, err := uncompr.NewReader(f)
	require.NoError(t, err)
	defer r.Close()

	body, err := io.ReadAll(r)
	require.NoError(t, err)

	return body
}
