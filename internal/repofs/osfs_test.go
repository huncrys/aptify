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

package repofs_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// errReader fails part way through, which is what a write has to survive
// without publishing anything.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

// entries lists the names directly below dir.
func entries(t *testing.T, dir string) []string {
	t.Helper()

	dirEntries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(dirEntries))
	for _, entry := range dirEntries {
		names = append(names, entry.Name())
	}

	return names
}

// TestWriteFilePublishesAtomically pins what the by-hash tree depends on: a
// published file is replaced rather than rewritten in place, so a second name
// serving its old bytes keeps them.
func TestWriteFilePublishesAtomically(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	require.NoError(t, fsys.WriteFile("Packages", []byte("first"), 0o644, time.Time{}))

	published, err := os.Stat(filepath.Join(dir, "Packages"))
	require.NoError(t, err)

	require.NoError(t, fsys.Clone("Packages", "entry"))

	require.NoError(t, fsys.WriteFile("Packages", []byte("second"), 0o644, time.Time{}))

	body, err := fs.ReadFile(fsys, "Packages")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), body)

	// The clone still holds what it was published as, which is what a client
	// asking for the old checksum gets.
	linked, err := fs.ReadFile(fsys, "entry")
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), linked)

	rewritten, err := os.Stat(filepath.Join(dir, "Packages"))
	require.NoError(t, err)
	assert.False(t, os.SameFile(published, rewritten),
		"the file was rewritten in place rather than replaced")
}

// TestWriteFileRecordsModificationTime covers the mtime a mirror sees: given
// one it is recorded, and a zero one leaves the file dated by the write.
func TestWriteFileRecordsModificationTime(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	mtime := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)

	require.NoError(t, fsys.WriteFile("dated", []byte("dated"), 0o644, mtime))

	fi, err := fsys.Stat("dated")
	require.NoError(t, err)
	assert.True(t, fi.ModTime().Equal(mtime), "got %s, want %s", fi.ModTime(), mtime)

	require.NoError(t, fsys.WriteFile("undated", []byte("undated"), 0o644, time.Time{}))

	fi, err = fsys.Stat("undated")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), fi.ModTime(), time.Minute)
}

// TestWriteFileSetsPermissions checks that the mode is the one asked for
// rather than the temporary's.
func TestWriteFileSetsPermissions(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	require.NoError(t, fsys.WriteFile("Packages", []byte("body"), 0o644, time.Time{}))

	fi, err := fsys.Stat("Packages")
	require.NoError(t, err)
	assert.Equal(t, fs.FileMode(0o644), fi.Mode().Perm())
}

// TestWriteLeavesNoTemporaries pins the two halves of the temporary's
// contract: a successful write leaves only the published file behind, and a
// failed one leaves nothing at all - neither a stray temporary nor a
// half written file under the published name.
func TestWriteLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	require.NoError(t, fsys.WriteFile("Packages", []byte("body"), 0o644, time.Time{}))
	assert.Equal(t, []string{"Packages"}, entries(t, dir))

	require.Error(t, fsys.WriteFrom("Contents-amd64", errReader{}, 0, time.Time{}))

	assert.Equal(t, []string{"Packages"}, entries(t, dir),
		"a failed write left something behind")
}

// TestWriteFromStreams covers the pool upload: the content arrives whole and
// carries the modification time of the file it came from.
func TestWriteFromStreams(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	body := bytes.Repeat([]byte("deb"), 4096)
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)

	require.NoError(t, fsys.MkdirAll("pool/main/h/hello"))
	require.NoError(t, fsys.WriteFrom("pool/main/h/hello/hello_1.0_amd64.deb",
		bytes.NewReader(body), int64(len(body)), mtime))

	published, err := fs.ReadFile(fsys, "pool/main/h/hello/hello_1.0_amd64.deb")
	require.NoError(t, err)
	assert.Equal(t, body, published)

	fi, err := fsys.Stat("pool/main/h/hello/hello_1.0_amd64.deb")
	require.NoError(t, err)
	assert.True(t, fi.ModTime().Equal(mtime), "got %s, want %s", fi.ModTime(), mtime)
}

// TestCloneSharesContent pins what makes a by-hash tree cost nothing: the
// clone is the very file rather than a copy of it.
func TestCloneSharesContent(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	require.NoError(t, fsys.WriteFile("Packages", []byte("body"), 0o644, time.Time{}))
	require.NoError(t, fsys.MkdirAll("by-hash/SHA256"))
	require.NoError(t, fsys.Clone("Packages", "by-hash/SHA256/cafebabe"))

	indice, err := os.Stat(filepath.Join(dir, "Packages"))
	require.NoError(t, err)

	entry, err := os.Stat(filepath.Join(dir, "by-hash", "SHA256", "cafebabe"))
	require.NoError(t, err)

	assert.True(t, os.SameFile(indice, entry), "the by-hash entry is a copy")

	// A second clone under a name already taken is an error rather than a
	// silent overwrite: the caller stats first, and a real collision means the
	// digest describes something else.
	assert.Error(t, fsys.Clone("Packages", "by-hash/SHA256/cafebabe"))
}

// TestChtimesTouches covers the by-hash retention clock: an entry is touched
// as it leaves the release, without its content being read or rewritten.
func TestChtimesTouches(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	old := time.Now().Add(-365 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, fsys.WriteFile("entry", []byte("body"), 0o644, old))

	now := time.Now().Truncate(time.Second)
	require.NoError(t, fsys.Chtimes("entry", now))

	fi, err := fsys.Stat("entry")
	require.NoError(t, err)
	assert.True(t, fi.ModTime().Equal(now), "got %s, want %s", fi.ModTime(), now)

	body, err := fs.ReadFile(fsys, "entry")
	require.NoError(t, err)
	assert.Equal(t, []byte("body"), body)
}

// TestRemove covers both deletions the pipeline makes: a single pool file and
// a whole stale indice directory.
func TestRemove(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	require.NoError(t, fsys.MkdirAll("dists/bookworm/main/binary-all"))
	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-all/Packages",
		[]byte("body"), 0o644, time.Time{}))
	require.NoError(t, fsys.WriteFile("dists/bookworm/main/Contents-all", []byte("body"), 0o644, time.Time{}))

	require.NoError(t, fsys.Remove("dists/bookworm/main/Contents-all"))
	_, err := fsys.Stat("dists/bookworm/main/Contents-all")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, fsys.RemoveAll("dists/bookworm/main/binary-all"))
	_, err = fsys.Stat("dists/bookworm/main/binary-all")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestGlobMatchesIndices checks the pattern the load stage finds a
// repository's whole recorded state with, and that a name is reported
// slash separated whatever the platform.
func TestGlobMatchesIndices(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	for _, name := range []string{
		"dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-arm64/Packages",
		"dists/trixie/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-amd64/Packages.gz",
		"dists/bookworm/main/Contents-amd64",
		"pool/main/h/hello/hello_1.0_amd64.deb",
	} {
		require.NoError(t, fsys.MkdirAll(path.Dir(name)))
		require.NoError(t, fsys.WriteFile(name, []byte(name), 0o644, time.Time{}))
	}

	matches, err := fsys.Glob("dists/*/*/binary-*/Packages")
	require.NoError(t, err)

	assert.Equal(t, []string{
		"dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-arm64/Packages",
		"dists/trixie/main/binary-amd64/Packages",
	}, matches)
}

// TestNamesOutsideTheRepositoryAreRejected checks the boundary os.DirFS draws
// for reads is drawn for writes too: nothing addresses a file outside the
// repository.
func TestNamesOutsideTheRepositoryAreRejected(t *testing.T) {
	dir := t.TempDir()
	fsys := repofs.NewOS(dir)

	for _, name := range []string{"../escape", "/etc/passwd", ""} {
		assert.ErrorIs(t, fsys.WriteFile(name, []byte("body"), 0o644, time.Time{}), fs.ErrInvalid, name)
		assert.ErrorIs(t, fsys.Remove(name), fs.ErrInvalid, name)
		assert.ErrorIs(t, fsys.MkdirAll(name), fs.ErrInvalid, name)
		assert.ErrorIs(t, fsys.Chtimes(name, time.Now()), fs.ErrInvalid, name)
	}

	assert.NoFileExists(t, filepath.Join(filepath.Dir(dir), "escape"))
}

// TestNameIsTheRoot checks that the repository reports where it lives, which
// is what the logs and error messages name it by.
func TestNameIsTheRoot(t *testing.T) {
	dir := t.TempDir()

	assert.Equal(t, dir, repofs.NewOS(dir).Name())
}
