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
	"context"
	"io/fs"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// TestS3WriteAndRead covers the publish and the read back: the content arrives
// whole, and the modification time it was published with is what the
// repository reports rather than the time of the upload.
func TestS3WriteAndRead(t *testing.T) {
	fsys := newTestS3(t)

	mtime := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)

	require.NoError(t, fsys.MkdirAll("dists/bookworm/main/binary-amd64"))
	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-amd64/Packages",
		[]byte("Package: hello-world\n"), 0o644, mtime))

	body, err := fs.ReadFile(fsys, "dists/bookworm/main/binary-amd64/Packages")
	require.NoError(t, err)
	assert.Equal(t, []byte("Package: hello-world\n"), body)

	fi, err := fsys.Stat("dists/bookworm/main/binary-amd64/Packages")
	require.NoError(t, err)
	assert.Equal(t, int64(len("Package: hello-world\n")), fi.Size())
	assert.True(t, fi.ModTime().Equal(mtime), "got %s, want %s", fi.ModTime(), mtime)
	assert.False(t, fi.IsDir())
}

// TestS3WriteFromStreams covers the pool upload, which is streamed rather than
// held in memory.
func TestS3WriteFromStreams(t *testing.T) {
	fsys := newTestS3(t)

	body := bytes.Repeat([]byte("deb"), 4096)
	mtime := time.Now().Add(-time.Hour).Truncate(time.Second)

	require.NoError(t, fsys.WriteFrom("pool/main/h/hello/hello_1.0_amd64.deb",
		bytes.NewReader(body), int64(len(body)), mtime))

	published, err := fs.ReadFile(fsys, "pool/main/h/hello/hello_1.0_amd64.deb")
	require.NoError(t, err)
	assert.Equal(t, body, published)

	fi, err := fsys.Stat("pool/main/h/hello/hello_1.0_amd64.deb")
	require.NoError(t, err)
	assert.True(t, fi.ModTime().Equal(mtime), "got %s, want %s", fi.ModTime(), mtime)
}

// TestS3MissingObjectsAreNotExist pins the mapping the pipeline branches on:
// an object that is not there has to look like a file that is not there, or an
// empty repository reads as a broken one.
func TestS3MissingObjectsAreNotExist(t *testing.T) {
	fsys := newTestS3(t)

	_, err := fsys.Open("dists/bookworm/InRelease")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	_, err = fsys.Stat("dists/bookworm/InRelease")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	_, err = fs.ReadFile(fsys, "dists/bookworm/InRelease")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	// An empty repository is what a first build starts from.
	_, err = fsys.Stat(".")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestS3StatsPrefixesAsDirectories covers the one thing a bucket has no
// concept of: the pipeline stats a directory to find out whether an older
// build left indices behind.
func TestS3StatsPrefixesAsDirectories(t *testing.T) {
	fsys := newTestS3(t)

	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-all/Packages",
		[]byte("body"), 0o644, time.Time{}))

	fi, err := fsys.Stat("dists/bookworm/main/binary-all")
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, "binary-all", fi.Name())

	root, err := fsys.Stat(".")
	require.NoError(t, err)
	assert.True(t, root.IsDir())
}

// TestS3ReadDir pins what a walk sees: the objects directly below a prefix,
// and the prefixes below it as directories.
func TestS3ReadDir(t *testing.T) {
	fsys := newTestS3(t)

	for _, name := range []string{
		"dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-amd64/by-hash/SHA256/cafebabe",
		"dists/bookworm/main/Contents-amd64",
	} {
		require.NoError(t, fsys.WriteFile(name, []byte(name), 0o644, time.Time{}))
	}

	entries, err := fsys.ReadDir("dists/bookworm/main/binary-amd64")
	require.NoError(t, err)

	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = entry.IsDir()
	}

	assert.Equal(t, map[string]bool{"Packages": false, "by-hash": true}, names)
}

// TestS3Glob covers the pattern the load stage finds a repository's whole
// recorded state with.
func TestS3Glob(t *testing.T) {
	fsys := newTestS3(t)

	for _, name := range []string{
		"dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-arm64/Packages",
		"dists/trixie/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-amd64/Packages.gz",
		"dists/bookworm/main/Contents-amd64",
		"pool/main/h/hello/hello_1.0_amd64.deb",
	} {
		require.NoError(t, fsys.WriteFile(name, []byte(name), 0o644, time.Time{}))
	}

	matches, err := fsys.Glob("dists/*/*/binary-*/Packages")
	require.NoError(t, err)

	assert.Equal(t, []string{
		"dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-arm64/Packages",
		"dists/trixie/main/binary-amd64/Packages",
	}, matches)

	// The release assembly globs a directory at a time.
	matches, err = fsys.Glob("dists/bookworm/*/Contents-*")
	require.NoError(t, err)
	assert.Equal(t, []string{"dists/bookworm/main/Contents-amd64"}, matches)
}

// TestS3Clone pins the by-hash publish: the entry serves the index's bytes,
// and it is a second object rather than a second upload.
func TestS3Clone(t *testing.T) {
	fsys := newTestS3(t)

	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-amd64/Packages",
		[]byte("body"), 0o644, time.Time{}))

	require.NoError(t, fsys.Clone("dists/bookworm/main/binary-amd64/Packages",
		"dists/bookworm/main/binary-amd64/by-hash/SHA256/cafebabe"))

	entry, err := fs.ReadFile(fsys, "dists/bookworm/main/binary-amd64/by-hash/SHA256/cafebabe")
	require.NoError(t, err)
	assert.Equal(t, []byte("body"), entry)

	// Replacing the index leaves the entry serving what it was published as,
	// which is the whole point of the tree.
	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-amd64/Packages",
		[]byte("newer"), 0o644, time.Time{}))

	entry, err = fs.ReadFile(fsys, "dists/bookworm/main/binary-amd64/by-hash/SHA256/cafebabe")
	require.NoError(t, err)
	assert.Equal(t, []byte("body"), entry)
}

// TestS3Chtimes covers the by-hash retention clock: an entry is touched
// without its content being uploaded again.
func TestS3Chtimes(t *testing.T) {
	fsys := newTestS3(t)

	old := time.Now().Add(-365 * 24 * time.Hour).Truncate(time.Second)
	require.NoError(t, fsys.WriteFile("entry", []byte("body"), 0o644, old))

	// Deliberately not the time of the touch: the object's own LastModified is
	// about to become now, and a backend that ignored the metadata would then
	// pass this test by accident.
	touched := time.Date(2001, 9, 9, 1, 46, 40, 123456789, time.UTC)
	require.NoError(t, fsys.Chtimes("entry", touched))

	fi, err := fsys.Stat("entry")
	require.NoError(t, err)
	assert.True(t, fi.ModTime().Equal(touched), "got %s, want %s", fi.ModTime(), touched)

	body, err := fs.ReadFile(fsys, "entry")
	require.NoError(t, err)
	assert.Equal(t, []byte("body"), body)
}

// TestS3Remove covers both deletions the pipeline makes: one pool file, and a
// whole stale indice directory.
func TestS3Remove(t *testing.T) {
	fsys := newTestS3(t)

	for _, name := range []string{
		"dists/bookworm/main/binary-all/Packages",
		"dists/bookworm/main/binary-all/Packages.gz",
		"dists/bookworm/main/binary-all/by-hash/SHA256/cafebabe",
		"dists/bookworm/main/Contents-all",
		"dists/bookworm/main/binary-amd64/Packages",
	} {
		require.NoError(t, fsys.WriteFile(name, []byte(name), 0o644, time.Time{}))
	}

	require.NoError(t, fsys.Remove("dists/bookworm/main/Contents-all"))
	_, err := fsys.Stat("dists/bookworm/main/Contents-all")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	require.NoError(t, fsys.RemoveAll("dists/bookworm/main/binary-all"))

	_, err = fsys.Stat("dists/bookworm/main/binary-all")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	// Only that prefix, and nothing that merely starts with the same letters.
	_, err = fsys.Stat("dists/bookworm/main/binary-amd64/Packages")
	assert.NoError(t, err)
}

// TestS3Prefix pins that a repository below a key prefix stays inside it: the
// names the pipeline uses are relative to the prefix, and nothing addresses a
// key outside it.
func TestS3Prefix(t *testing.T) {
	backend := newTestBackend(t)

	root := repofs.NewS3(context.Background(), backend.client, backend.bucket, "")
	nested := repofs.NewS3(context.Background(), backend.client, backend.bucket, "/apt/debian/")

	require.NoError(t, nested.WriteFile("dists/bookworm/InRelease", []byte("signed"), 0o644, time.Time{}))

	body, err := fs.ReadFile(root, "apt/debian/dists/bookworm/InRelease")
	require.NoError(t, err)
	assert.Equal(t, []byte("signed"), body)

	matches, err := nested.Glob("dists/*/InRelease")
	require.NoError(t, err)
	assert.Equal(t, []string{"dists/bookworm/InRelease"}, matches)

	assert.Equal(t, "s3://"+path.Join(backend.bucket, "apt/debian"), nested.Name())

	for _, name := range []string{"../escape", "/etc/passwd", ""} {
		assert.ErrorIs(t, nested.WriteFile(name, []byte("body"), 0o644, time.Time{}), fs.ErrInvalid, name)
		assert.ErrorIs(t, nested.Remove(name), fs.ErrInvalid, name)
		assert.ErrorIs(t, nested.MkdirAll(name), fs.ErrInvalid, name)
		assert.ErrorIs(t, nested.Chtimes(name, time.Now()), fs.ErrInvalid, name)
	}
}
