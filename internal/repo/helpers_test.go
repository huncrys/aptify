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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
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
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/contents"
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
		FS:             repofs.NewOS(repoDir),
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

	return snapshotTreeFS(t, os.DirFS(dir))
}

// snapshotTreeFS is the same snapshot of a repository wherever it is
// published, which is what lets one invariant be checked against a directory
// and against a bucket.
func snapshotTreeFS(t *testing.T, fsys fs.FS) map[string]treeEntry {
	t.Helper()

	tree := make(map[string]treeEntry)

	require.NoError(t, fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Statted rather than taken from the walk: a listing carries the time
		// of the upload, and what a mirror sees is the recorded one.
		fi, err := fs.Stat(fsys, name)
		if err != nil {
			return err
		}

		sums, err := hashsum.File(fsys, name)
		if err != nil {
			return err
		}

		tree[name] = treeEntry{sha256: sums.SHA256, mtime: fi.ModTime()}

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

	verifyRepoFS(t, os.DirFS(repoDir), releases...)
}

// verifyRepoFS is the same verification against a repository wherever it is
// published: everything it reads goes through the filesystem it was built on.
func verifyRepoFS(t *testing.T, repoFS fs.FS, releases ...string) {
	t.Helper()

	for _, release := range releases {
		releaseFS, err := fs.Sub(repoFS, path.Join("dists", release))
		require.NoError(t, err)

		// The keyring is what makes this a verification rather than a read: a
		// release signed by anything else fails to decode.
		signed := decodeReleaseFS(t, releaseFS, "InRelease", openpgp.EntityList{testEntity(t)})

		// Release carries the same stanza without the clearsigning, and
		// Release.gpg signs exactly those bytes.
		plain := decodeReleaseFS(t, releaseFS, "Release", nil)
		require.Equal(t, plain, signed, "Release and InRelease disagree in %s", release)

		verifyDetachedSignature(t, releaseFS)

		require.NotEmpty(t, signed.SHA256, "%s publishes no checksums", release)
		require.NotEmpty(t, signed.Components)
		require.NotEmpty(t, signed.Architectures)

		// Every file the release names, hashed once and checked against all
		// three lists.
		sumsByName := make(map[string]hashsum.Sums, len(signed.SHA256))
		for _, entry := range signed.SHA256 {
			sums, err := hashsum.File(releaseFS, entry.Filename)
			require.NoError(t, err, "%s names a file that is not published: %s", release, entry.Filename)

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

		verifyIndiceVariants(t, releaseFS, release, sumsByName)
	}
}

// verifyIndiceVariants checks that every index is listed under its
// uncompressed name as well as its compressed ones - apt resolves a target by
// the uncompressed key and only then picks a variant to fetch - and that all of
// them decompress to the same bytes.
func verifyIndiceVariants(t *testing.T, releaseFS fs.FS, release string, listed map[string]hashsum.Sums) {
	t.Helper()

	for name := range listed {
		base := path.Base(name)

		switch {
		case strings.HasSuffix(name, ".gz"), strings.HasSuffix(name, ".xz"):
			uncompressed := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".xz")
			require.Contains(t, listed, uncompressed,
				"%s: %s is published without its uncompressed variant", release, name)

			want, err := fs.ReadFile(releaseFS, uncompressed)
			require.NoError(t, err)

			require.Equal(t, want, decompressFS(t, releaseFS, name),
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

	dir, name := filepath.Split(releasePath)

	return decodeReleaseFS(t, os.DirFS(dir), name, keyring)
}

// decodeReleaseFS is the same read of a release published anywhere.
func decodeReleaseFS(t *testing.T, releaseFS fs.FS, name string, keyring openpgp.EntityList) types.Release {
	t.Helper()

	releaseFile, err := releaseFS.Open(name)
	require.NoError(t, err)
	defer func() { _ = releaseFile.Close() }()

	decoder, err := deb822.NewDecoder(releaseFile, keyring)
	require.NoError(t, err)

	if keyring != nil {
		require.NotNil(t, decoder.Signer(), "%s is not signed by the repository key", name)
	}

	var release types.Release
	require.NoError(t, decoder.Decode(&release))

	return release
}

// verifyDetachedSignature checks Release.gpg against Release.
func verifyDetachedSignature(t *testing.T, releaseFS fs.FS) {
	t.Helper()

	body, err := releaseFS.Open("Release")
	require.NoError(t, err)
	defer func() { _ = body.Close() }()

	signature, err := releaseFS.Open("Release.gpg")
	require.NoError(t, err)
	defer func() { _ = signature.Close() }()

	signer, err := openpgp.CheckArmoredDetachedSignature(
		openpgp.EntityList{testEntity(t)}, body, signature, nil)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

// The release and component most of the end to end tests publish into.
const (
	testReleaseName   = "bookworm"
	testComponentName = "stable"
)

// componentConfig is one component of the release testConfig builds.
func componentConfig(name string, maxVersions uint, packages ...string) v1alpha1.ComponentConfig {
	return v1alpha1.ComponentConfig{Name: name, Packages: packages, MaxVersions: maxVersions}
}

// releaseConfig is one release of the configuration testConfig builds.
func releaseConfig(name string, components ...v1alpha1.ComponentConfig) v1alpha1.ReleaseConfig {
	return v1alpha1.ReleaseConfig{
		Name:        name,
		Version:     "12",
		Origin:      "Demo Organization",
		Label:       "Demo",
		Suite:       name,
		Description: "Demo repository",
		Components:  components,
	}
}

// testConfig is a configuration over the given releases.
func testConfig(releases ...v1alpha1.ReleaseConfig) *v1alpha1.Repository {
	return &v1alpha1.Repository{Releases: releases}
}

// singleComponentConfig is the shape most of these tests want: one release,
// one component, over the named .deb files.
func singleComponentConfig(maxVersions uint, packages ...string) *v1alpha1.Repository {
	return testConfig(releaseConfig(testReleaseName,
		componentConfig(testComponentName, maxVersions, packages...)))
}

// distPath addresses a file below a release's component directory.
func distPath(repoDir, release, component string, elem ...string) string {
	return filepath.Join(append([]string{repoDir, "dists", release, component}, elem...)...)
}

// distName is the same file as distPath, named the way the pipeline addresses
// it: relative to the repository root and slash separated.
func distName(release, component string, elem ...string) string {
	return path.Join(append([]string{"dists", release, component}, elem...)...)
}

// mustSub is the subtree of a repository below a name.
func mustSub(t *testing.T, fsys fs.FS, name string) fs.FS {
	t.Helper()

	sub, err := fs.Sub(fsys, name)
	require.NoError(t, err)

	return sub
}

// onlyAddedUnder is the one name below prefix that the second snapshot has and
// the first does not, failing when there is more or less than one.
func onlyAddedUnder(t *testing.T, prefix string, before, after map[string]treeEntry) string {
	t.Helper()

	var added []string
	for name := range after {
		if _, ok := before[name]; !ok && strings.HasPrefix(name, prefix) {
			added = append(added, name)
		}
	}
	slices.Sort(added)

	require.Len(t, added, 1, "files added under %s", prefix)

	return added[0]
}

// packagesIn decodes the Packages indice of one architecture of the test
// release and component.
func packagesIn(t *testing.T, repoDir, architecture string) []types.Package {
	t.Helper()

	return decodePackages(t, distPath(repoDir, testReleaseName, testComponentName,
		"binary-"+architecture, "Packages"))
}

// packageVersions lists the "<name> <version> <architecture>" of every stanza,
// which is what a Packages indice is compared by.
func packageVersions(packages []types.Package) []string {
	keys := make([]string, 0, len(packages))
	for _, pkg := range packages {
		keys = append(keys, fmt.Sprintf("%s %s %s", pkg.Name, pkg.Version, pkg.Architecture))
	}
	slices.Sort(keys)

	return keys
}

// readContents reads a published Contents indice into the packages each path
// is attributed to.
func readContents(t *testing.T, filePath string) map[string][]string {
	t.Helper()

	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := uncompr.NewReader(f)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	entries := make(map[string][]string)

	cr := contents.NewReader(r)
	for {
		entry, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		entries[entry.Path] = entry.Packages
	}

	return entries
}

// fileMTime is the modification time a mirror would see.
func fileMTime(t *testing.T, filePath string) stdtime.Time {
	t.Helper()

	fi, err := os.Stat(filePath)
	require.NoError(t, err)

	return fi.ModTime()
}

// debFixture describes a .deb to synthesise. The checked in packages ship the
// same paths whatever their version, so a test that has to tell one version's
// published contents from another builds its own.
type debFixture struct {
	name         string
	version      string
	architecture string
	// description is the control field, which is what a reread of the pool has
	// to pick up.
	description string
	// files is the data archive, keyed by the path inside the package.
	files map[string]string
}

// buildTestDeb writes the package the fixture describes into dir and returns
// its path.
func buildTestDeb(t *testing.T, dir string, fixture debFixture) string {
	t.Helper()

	description := fixture.description
	if description == "" {
		description = "a synthetic test package"
	}

	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n"+
		"Maintainer: Test User <test@example.com>\nSection: misc\nPriority: optional\n"+
		"Description: %s\n",
		fixture.name, fixture.version, fixture.architecture, description)

	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")

	for _, member := range []struct {
		name string
		body []byte
	}{
		{name: "debian-binary", body: []byte("2.0\n")},
		{name: "control.tar.gz", body: tarGzip(t, map[string]string{"control": control})},
		{name: "data.tar.gz", body: tarGzip(t, fixture.files)},
	} {
		// name, mtime, uid, gid, mode, size, then the ar magic; a member of odd
		// length is padded to the next even offset.
		fmt.Fprintf(&archive, "%-16s%-12d%-6d%-6d%-8o%-10d`\n",
			member.name, 0, 0, 0, 0o100644, len(member.body))

		archive.Write(member.body)
		if len(member.body)%2 != 0 {
			archive.WriteByte('\n')
		}
	}

	debFilePath := filepath.Join(dir,
		fmt.Sprintf("%s_%s_%s.deb", fixture.name, fixture.version, fixture.architecture))
	require.NoError(t, os.WriteFile(debFilePath, archive.Bytes(), 0o644))

	return debFilePath
}

// tarGzip renders the files, and the directories leading to them, as a gzipped
// tar archive.
func tarGzip(t *testing.T, files map[string]string) []byte {
	t.Helper()

	directories := make(map[string]bool)
	for name := range files {
		for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			directories[dir] = true
		}
	}

	var buf bytes.Buffer

	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, dir := range slices.Sorted(maps.Keys(directories)) {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     dir + "/",
			Mode:     0o755,
		}))
	}

	for _, name := range slices.Sorted(maps.Keys(files)) {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(files[name])),
		}))

		_, err := tarWriter.Write([]byte(files[name]))
		require.NoError(t, err)
	}

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())

	return buf.Bytes()
}

// decompressFS returns the content of a compressed index.
func decompressFS(t *testing.T, fsys fs.FS, name string) []byte {
	t.Helper()

	f, err := fsys.Open(name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	r, err := uncompr.NewReader(f)
	require.NoError(t, err)
	defer func() { _ = r.Close() }()

	body, err := io.ReadAll(r)
	require.NoError(t, err)

	return body
}
