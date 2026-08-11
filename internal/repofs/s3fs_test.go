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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// TestS3RemoveAllToleratesMissingKeys covers the implementations that answer a
// delete of a key that is not there with an error rather than with a success.
// RemoveAll batches the name's own key in with the listing, and that key is not
// an object at all when the name is only a prefix, which is every directory the
// pipeline removes.
func TestS3RemoveAllToleratesMissingKeys(t *testing.T) {
	backend := newTestBackend(t)
	fsys := repofs.NewS3(context.Background(), &strictDeleteClient{S3API: backend.client}, backend.bucket, "")

	for _, name := range []string{
		"dists/bookworm/main/binary-all/Packages",
		"dists/bookworm/main/binary-all/by-hash/SHA256/cafebabe",
		"dists/bookworm/main/binary-amd64/Packages",
	} {
		require.NoError(t, fsys.WriteFile(name, []byte(name), 0o644, time.Time{}))
	}

	require.NoError(t, fsys.RemoveAll("dists/bookworm/main/binary-all"))

	_, err := fsys.Stat("dists/bookworm/main/binary-all")
	assert.ErrorIs(t, err, fs.ErrNotExist)

	_, err = fsys.Stat("dists/bookworm/main/binary-amd64/Packages")
	assert.NoError(t, err)

	// Removing what was never published is a no-op, the same as os.RemoveAll.
	require.NoError(t, fsys.RemoveAll("dists/bookworm/main/binary-all"))
}

// TestS3RemoveAllReportsRealErrors is the other half: tolerating a missing key
// must not swallow a delete that genuinely failed.
func TestS3RemoveAllReportsRealErrors(t *testing.T) {
	backend := newTestBackend(t)
	client := &strictDeleteClient{S3API: backend.client, failCode: "AccessDenied"}
	fsys := repofs.NewS3(context.Background(), client, backend.bucket, "")

	require.NoError(t, fsys.WriteFile("dists/bookworm/main/binary-all/Packages", []byte("body"), 0o644, time.Time{}))

	err := fsys.RemoveAll("dists/bookworm/main/binary-all")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
	assert.Contains(t, err.Error(), "dists/bookworm/main/binary-all/Packages")
}

// strictDeleteClient answers a batched delete the way the implementations that
// do not follow Amazon here do: a key that is not there comes back as a
// NoSuchKey error entry instead of being reported as deleted. With failCode set
// every key fails with that code instead, which is what a delete that really
// went wrong looks like.
type strictDeleteClient struct {
	repofs.S3API

	failCode string
}

func (c *strictDeleteClient) DeleteObjects(ctx context.Context, in *s3.DeleteObjectsInput,
	opts ...func(*s3.Options),
) (*s3.DeleteObjectsOutput, error) {
	var (
		present  []s3types.ObjectIdentifier
		failures []s3types.Error
	)

	for _, object := range in.Delete.Objects {
		if c.failCode != "" {
			failures = append(failures, s3types.Error{
				Key:     object.Key,
				Code:    aws.String(c.failCode),
				Message: aws.String("delete refused"),
			})

			continue
		}

		if _, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: in.Bucket, Key: object.Key}); err != nil {
			failures = append(failures, s3types.Error{
				Key:     object.Key,
				Code:    aws.String("NoSuchKey"),
				Message: aws.String("key not found"),
			})

			continue
		}

		present = append(present, object)
	}

	out := &s3.DeleteObjectsOutput{}

	if len(present) > 0 {
		var err error

		out, err = c.S3API.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: in.Bucket,
			Delete: &s3types.Delete{Objects: present, Quiet: in.Delete.Quiet},
		}, opts...)
		if err != nil {
			return nil, err
		}
	}

	out.Errors = append(out.Errors, failures...)

	return out, nil
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
