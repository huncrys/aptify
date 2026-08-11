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

package repofs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// deleteBatchSize is how many keys one DeleteObjects call carries, which is
// the most S3 accepts.
const deleteBatchSize = 1000

// S3API is the part of the S3 client a repository uses. Taking it as an
// interface is what lets the backend be driven by a fake.
type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CopyObject(context.Context, *s3.CopyObjectInput, ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	DeleteObjects(context.Context, *s3.DeleteObjectsInput, ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// s3FS is a repository published to an S3 bucket, optionally below a key
// prefix. There are no directories: a name is a key, and what a walk sees as a
// directory is a set of keys sharing a prefix.
//
// Every publish is a single PUT, which is atomic per key, so the dot-prefixed
// temporary a local write goes through has no counterpart here: a failed PUT
// publishes nothing.
type s3FS struct {
	client S3API
	bucket string
	// prefix is the key prefix of the repository root, empty or ending in a
	// slash.
	prefix string
	// ctx is the context every request is made with. The io/fs surface takes
	// none, so the one the build was started with is held here.
	ctx context.Context
}

var _ FS = (*s3FS)(nil)

// NewS3 is the repository stored in a bucket, below an optional key prefix.
func NewS3(ctx context.Context, client S3API, bucket, prefix string) FS {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}

	return &s3FS{client: client, bucket: bucket, prefix: prefix, ctx: ctx}
}

func (s *s3FS) Name() string {
	return "s3://" + path.Join(s.bucket, strings.TrimSuffix(s.prefix, "/"))
}

// key is the object key a repository relative name is published under.
func (s *s3FS) key(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "path", Path: name, Err: fs.ErrInvalid}
	}

	if name == "." {
		return strings.TrimSuffix(s.prefix, "/"), nil
	}

	return s.prefix + name, nil
}

// dirPrefix is the key prefix everything below a name is published under.
func (s *s3FS) dirPrefix(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "path", Path: name, Err: fs.ErrInvalid}
	}

	if name == "." {
		return s.prefix, nil
	}

	return s.prefix + name + "/", nil
}

func (s *s3FS) Open(name string) (fs.File, error) {
	key, err := s.key(name)
	if err != nil {
		return nil, err
	}

	out, err := s.client.GetObject(s.ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, pathError("open", name, err)
	}

	return &s3File{
		body: out.Body,
		info: fileInfo{
			name:    path.Base(name),
			size:    aws.ToInt64(out.ContentLength),
			modTime: objectMtime(out.Metadata, out.LastModified),
		},
	}, nil
}

func (s *s3FS) Stat(name string) (fs.FileInfo, error) {
	key, err := s.key(name)
	if err != nil {
		return nil, err
	}

	if name != "." {
		out, err := s.client.HeadObject(s.ctx, &s3.HeadObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    aws.String(key),
		})
		if err == nil {
			return fileInfo{
				name:    path.Base(name),
				size:    aws.ToInt64(out.ContentLength),
				modTime: objectMtime(out.Metadata, out.LastModified),
			}, nil
		}

		if !isNotFound(err) {
			return nil, pathError("stat", name, err)
		}
	}

	// No object under the name itself, so this is a directory if anything is
	// published below it. There is nothing to record a modification time on.
	prefix, err := s.dirPrefix(name)
	if err != nil {
		return nil, err
	}

	out, err := s.client.ListObjectsV2(s.ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return nil, pathError("stat", name, err)
	}

	if len(out.Contents) == 0 {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}

	return fileInfo{name: path.Base(name), dir: true}, nil
}

func (s *s3FS) ReadDir(name string) ([]fs.DirEntry, error) {
	prefix, err := s.dirPrefix(name)
	if err != nil {
		return nil, err
	}

	var entries []fs.DirEntry

	err = s.eachPage(prefix, aws.String("/"), func(page *s3.ListObjectsV2Output) {
		for _, commonPrefix := range page.CommonPrefixes {
			child := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(commonPrefix.Prefix), prefix), "/")
			if child == "" {
				continue
			}

			entries = append(entries, dirEntry{fileInfo{name: child, dir: true}})
		}

		for _, object := range page.Contents {
			child := strings.TrimPrefix(aws.ToString(object.Key), prefix)
			if child == "" {
				continue
			}

			// The listing carries no metadata, so an entry is dated by the
			// object's own LastModified. Stat is what reports a recorded
			// mtime; nothing walking a directory needs one.
			entries = append(entries, dirEntry{fileInfo{
				name:    child,
				size:    aws.ToInt64(object.Size),
				modTime: aws.ToTime(object.LastModified),
			}})
		}
	})
	if err != nil {
		return nil, pathError("readdir", name, err)
	}

	slices.SortFunc(entries, func(a, b fs.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})

	return entries, nil
}

// Glob lists the keys below the pattern's literal prefix and matches them
// against it, rather than walking the tree a directory at a time: one listing
// answers a whole pattern.
func (s *s3FS) Glob(pattern string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}

	prefix, err := s.dirPrefix(literalPrefix(pattern))
	if err != nil {
		return nil, err
	}

	var matches []string

	err = s.eachPage(prefix, nil, func(page *s3.ListObjectsV2Output) {
		for _, object := range page.Contents {
			name := strings.TrimPrefix(aws.ToString(object.Key), s.prefix)
			if matched, _ := path.Match(pattern, name); matched {
				matches = append(matches, name)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", pattern, err)
	}

	slices.Sort(matches)

	return matches, nil
}

// WriteFile publishes body under name. A PUT is atomic per key, so there is
// nothing to rename into place.
func (s *s3FS) WriteFile(name string, body []byte, _ fs.FileMode, mtime time.Time) error {
	return s.put(name, bytes.NewReader(body), int64(len(body)), mtime)
}

func (s *s3FS) WriteFrom(name string, r io.Reader, size int64, mtime time.Time) error {
	return s.put(name, r, size, mtime)
}

func (s *s3FS) put(name string, body io.Reader, size int64, mtime time.Time) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}

	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	}

	if !mtime.IsZero() {
		input.Metadata = map[string]string{mtimeMetadataKey: formatMtime(mtime)}
	}

	if _, err := s.client.PutObject(s.ctx, input); err != nil {
		return pathError("write", name, err)
	}

	return nil
}

// MkdirAll is a no-op: a key names its own directories.
func (s *s3FS) MkdirAll(name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}

	return nil
}

func (s *s3FS) Remove(name string) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}

	if _, err := s.client.DeleteObject(s.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}); err != nil {
		return pathError("remove", name, err)
	}

	return nil
}

// RemoveAll deletes the name and everything below it, a thousand keys per
// request. The name's own key goes into the batch and normally does not exist,
// so an error entry saying so is not a failure.
func (s *s3FS) RemoveAll(name string) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}

	prefix, err := s.dirPrefix(name)
	if err != nil {
		return err
	}

	var keys []string

	if err := s.eachPage(prefix, nil, func(page *s3.ListObjectsV2Output) {
		for _, object := range page.Contents {
			keys = append(keys, aws.ToString(object.Key))
		}
	}); err != nil {
		return pathError("removeall", name, err)
	}

	// The name may be an object in its own right as well as a prefix.
	keys = append(keys, key)

	for chunk := range slices.Chunk(keys, deleteBatchSize) {
		objects := make([]types.ObjectIdentifier, 0, len(chunk))
		for _, k := range chunk {
			objects = append(objects, types.ObjectIdentifier{Key: aws.String(k)})
		}

		out, err := s.client.DeleteObjects(s.ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)},
		})
		if err != nil {
			return pathError("removeall", name, err)
		}

		for _, failure := range out.Errors {
			// Deleting a key that is not there is a no-op by this package's
			// contract, as it is for os.RemoveAll, and the name's own key is
			// exactly that whenever the name is only a prefix. Amazon answers
			// such a delete with a success; other implementations report a
			// NoSuchKey error entry for it.
			if aws.ToString(failure.Code) == "NoSuchKey" {
				continue
			}

			return fmt.Errorf("failed to remove %s: %s: %s", aws.ToString(failure.Key),
				aws.ToString(failure.Code), aws.ToString(failure.Message))
		}
	}

	return nil
}

// Clone copies an object server side, so the bytes never travel through this
// process. It is the by-hash publish, and the entry is the whole point of the
// copy rather than of a second upload.
func (s *s3FS) Clone(oldname, newname string) error {
	from, err := s.key(oldname)
	if err != nil {
		return err
	}

	to, err := s.key(newname)
	if err != nil {
		return err
	}

	if _, err := s.client.CopyObject(s.ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(to),
		CopySource: aws.String(url.PathEscape(s.bucket + "/" + from)),
	}); err != nil {
		return pathError("clone", oldname, err)
	}

	return nil
}

// Chtimes records a modification time by copying the object onto itself with
// the metadata replaced, which is the only way to rewrite metadata without
// uploading the content again. Everything else the object carries is copied
// across, so a touch does not quietly drop its content type.
func (s *s3FS) Chtimes(name string, mtime time.Time) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}

	head, err := s.client.HeadObject(s.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return pathError("chtimes", name, err)
	}

	metadata := make(map[string]string, len(head.Metadata)+1)
	for k, v := range head.Metadata {
		metadata[k] = v
	}
	metadata[mtimeMetadataKey] = formatMtime(mtime)

	if _, err := s.client.CopyObject(s.ctx, &s3.CopyObjectInput{
		Bucket:            aws.String(s.bucket),
		Key:               aws.String(key),
		CopySource:        aws.String(url.PathEscape(s.bucket + "/" + key)),
		Metadata:          metadata,
		MetadataDirective: types.MetadataDirectiveReplace,
		ContentType:       head.ContentType,
	}); err != nil {
		return pathError("chtimes", name, err)
	}

	return nil
}

// eachPage lists everything under a prefix, handing each page to fn.
func (s *s3FS) eachPage(prefix string, delimiter *string, fn func(*s3.ListObjectsV2Output)) error {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket:    aws.String(s.bucket),
		Prefix:    aws.String(prefix),
		Delimiter: delimiter,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(s.ctx)
		if err != nil {
			return err
		}

		fn(page)
	}

	return nil
}

// s3File is an object opened for reading. It is a stream and nothing more:
// callers that need random access spill it to a scratch file.
type s3File struct {
	body io.ReadCloser
	info fileInfo
}

func (f *s3File) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *s3File) Read(b []byte) (int, error) { return f.body.Read(b) }
func (f *s3File) Close() error               { return f.body.Close() }

// fileInfo describes an object, or a prefix standing in for a directory.
type fileInfo struct {
	name    string
	size    int64
	modTime time.Time
	dir     bool
}

func (fi fileInfo) Name() string { return fi.name }
func (fi fileInfo) Size() int64  { return fi.size }

func (fi fileInfo) Mode() fs.FileMode {
	if fi.dir {
		return fs.ModeDir | 0o755
	}

	return 0o644
}

func (fi fileInfo) ModTime() time.Time { return fi.modTime }
func (fi fileInfo) IsDir() bool        { return fi.dir }
func (fi fileInfo) Sys() any           { return nil }

// dirEntry is a listed object or common prefix.
type dirEntry struct {
	info fileInfo
}

func (e dirEntry) Name() string               { return e.info.Name() }
func (e dirEntry) IsDir() bool                { return e.info.IsDir() }
func (e dirEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e.info, nil }

// objectMtime is the modification time an object reports: the one recorded in
// its metadata, or the time it was last written when it carries none.
func objectMtime(metadata map[string]string, lastModified *time.Time) time.Time {
	for key, value := range metadata {
		// The SDK lowercases metadata keys, but a fake or a proxy in front of
		// the bucket need not.
		if !strings.EqualFold(key, mtimeMetadataKey) {
			continue
		}

		if mtime, ok := parseMtime(value); ok {
			return mtime
		}
	}

	return aws.ToTime(lastModified)
}

// literalPrefix is the leading part of a glob pattern that matches itself, so
// that a listing can be narrowed to it.
func literalPrefix(pattern string) string {
	if i := strings.IndexAny(pattern, "*?[\\"); i >= 0 {
		pattern = pattern[:i]
	}

	dir := path.Dir(pattern)
	if dir == "/" {
		return "."
	}

	return dir
}

// pathError reports a failed operation as io/fs does, mapping a missing object
// onto fs.ErrNotExist: the pipeline branches on it to tell an empty repository
// from a broken one.
func pathError(op, name string, err error) error {
	if isNotFound(err) {
		return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
	}

	return &fs.PathError{Op: op, Path: name, Err: err}
}

// isNotFound reports whether the error says the object is not there. The SDK
// models it as one of two types depending on the operation, and a
// non-Amazon implementation may only give the code back.
func isNotFound(err error) bool {
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}

	var notFound *types.NotFound
	if errors.As(err, &notFound) {
		return true
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "NoSuchBucket", "404":
			return true
		}
	}

	return false
}
