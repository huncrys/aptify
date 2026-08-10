// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
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

// Package hashsum computes the checksums an archive publishes for a file, all
// of them in a single pass so that they can never describe different bytes.
package hashsum

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"oaklab.hu/debian/deb822/types/filehash"
	"oaklab.hu/debian/deb822/types/list"
)

// ByHashDirName is the directory an index's by-hash entries are published in,
// relative to the index itself.
const ByHashDirName = "by-hash"

// Sums holds every checksum of one file, plus the size the Release file
// publishes alongside them.
type Sums struct {
	// Path is the file's path relative to the directory it was hashed in.
	Path string
	Size int64

	MD5    string
	SHA1   string
	SHA256 string
}

// Digest is one algorithm's checksum of a file.
type Digest struct {
	// Algorithm is spelled as in the Release stanza: MD5Sum, SHA1 or SHA256.
	Algorithm string
	Hash      string
}

// Digests returns the file's checksums, one per published algorithm.
func (s Sums) Digests() []Digest {
	return []Digest{
		{Algorithm: "MD5Sum", Hash: s.MD5},
		{Algorithm: "SHA1", Hash: s.SHA1},
		{Algorithm: "SHA256", Hash: s.SHA256},
	}
}

// File returns every checksum of the file at path. Path is reported as given.
func File(path string) (Sums, error) {
	f, err := os.Open(path)
	if err != nil {
		return Sums{}, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	size, err := io.Copy(io.MultiWriter(md5Hash, sha1Hash, sha256Hash), f)
	if err != nil {
		return Sums{}, fmt.Errorf("failed to hash file: %w", err)
	}

	return Sums{
		Path:   path,
		Size:   size,
		MD5:    sum(md5Hash),
		SHA1:   sum(sha1Hash),
		SHA256: sum(sha256Hash),
	}, nil
}

// Directory returns the checksums of every file under dir matching one of the
// globs, with paths relative to dir. by-hash trees are skipped: their entries
// are hard links to files that are hashed under their own names, and a Release
// file must not list them. Dot-prefixed files are skipped as well, so a
// concurrent build's temporaries are never signed for.
func Directory(dir string, globs []string) ([]Sums, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of directory: %w", err)
	}

	var sums []Sums

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ByHashDirName {
				return fs.SkipDir
			}

			return nil
		}

		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		matched := len(globs) == 0
		for _, glob := range globs {
			if matched {
				break
			}

			matched, _ = filepath.Match(filepath.Join(dir, glob), path)
		}

		if !matched {
			return nil
		}

		fileSums, err := File(path)
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileSums.Path = filepath.ToSlash(relativePath)

		sums = append(sums, fileSums)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return sums, nil
}

// MD5List returns the MD5Sum entries of a Release file.
func MD5List(sums []Sums) list.NewLineDelimited[filehash.FileHash] {
	return hashList(sums, func(s Sums) string { return s.MD5 })
}

// SHA1List returns the SHA1 entries of a Release file.
func SHA1List(sums []Sums) list.NewLineDelimited[filehash.FileHash] {
	return hashList(sums, func(s Sums) string { return s.SHA1 })
}

// SHA256List returns the SHA256 entries of a Release file.
func SHA256List(sums []Sums) list.NewLineDelimited[filehash.FileHash] {
	return hashList(sums, func(s Sums) string { return s.SHA256 })
}

func hashList(sums []Sums, digest func(Sums) string) list.NewLineDelimited[filehash.FileHash] {
	hashes := make(list.NewLineDelimited[filehash.FileHash], 0, len(sums))
	for _, s := range sums {
		hashes = append(hashes, filehash.FileHash{
			Filename: s.Path,
			Hash:     digest(s),
			Size:     s.Size,
		})
	}

	return hashes
}

func sum(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}
