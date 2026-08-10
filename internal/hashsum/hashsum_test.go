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

package hashsum

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"oaklab.hu/debian/deb822/types/filehash"
	"oaklab.hu/debian/deb822/types/list"
)

// releaseIndiceGlobs is the glob list aptify hashes a release directory with.
var releaseIndiceGlobs = []string{"*/binary-*/Packages*", "*/binary-*/Release", "*/Contents-*"}

// TestFile pins the digests against published test vectors, so that no
// algorithm can quietly end up describing something else.
func TestFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "abc")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}

	sums, err := File(path)
	if err != nil {
		t.Fatal(err)
	}

	if sums.Size != 3 {
		t.Errorf("size: got %d, want 3", sums.Size)
	}

	for _, tc := range []struct{ name, got, want string }{
		{"MD5", sums.MD5, "900150983cd24fb0d6963f7d28e17f72"},
		{"SHA1", sums.SHA1, "a9993e364706816aba3e25717850c26c9cd0d89d"},
		{"SHA256", sums.SHA256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, tc.got, tc.want)
		}
	}

	wantDigests := []Digest{
		{Algorithm: "MD5Sum", Hash: sums.MD5},
		{Algorithm: "SHA1", Hash: sums.SHA1},
		{Algorithm: "SHA256", Hash: sums.SHA256},
	}
	if !slices.Equal(sums.Digests(), wantDigests) {
		t.Errorf("digests: got %v, want %v", sums.Digests(), wantDigests)
	}
}

// TestDirectory covers which files a release directory publishes checksums
// for. The exclusions are the load bearing part: a by-hash entry is a hard
// link to a file listed under its own name, and a temporary belongs to a build
// that has not published anything yet.
func TestDirectory(t *testing.T) {
	dir := t.TempDir()

	files := []string{
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
		"pool/main/h/hello/hello_1.0_amd64.deb",
	}

	for _, name := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sums, err := Directory(dir, releaseIndiceGlobs)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, s := range sums {
		got = append(got, s.Path)
	}
	slices.Sort(got)

	want := []string{
		"main/Contents-amd64",
		"main/Contents-amd64.gz",
		"main/binary-amd64/Packages",
		"main/binary-amd64/Packages.gz",
		"main/binary-amd64/Packages.xz",
		"main/binary-amd64/Release",
	}

	if !slices.Equal(got, want) {
		t.Errorf("hashed files:\n got %q\nwant %q", got, want)
	}

	for _, s := range sums {
		if s.Size != int64(len(s.Path)) || s.MD5 == "" || s.SHA1 == "" || s.SHA256 == "" {
			t.Errorf("incomplete sums for %s: %+v", s.Path, s)
		}
	}
}

// TestLists checks that the Release file entries describe the files they were
// computed from, algorithm by algorithm.
func TestLists(t *testing.T) {
	sums := []Sums{{Path: "main/binary-amd64/Packages", Size: 3, MD5: "md5", SHA1: "sha1", SHA256: "sha256"}}

	for _, tc := range []struct {
		name   string
		hash   string
		hashes list.NewLineDelimited[filehash.FileHash]
	}{
		{"MD5Sum", "md5", MD5List(sums)},
		{"SHA1", "sha1", SHA1List(sums)},
		{"SHA256", "sha256", SHA256List(sums)},
	} {
		if len(tc.hashes) != 1 {
			t.Fatalf("%s list: got %d entries, want 1", tc.name, len(tc.hashes))
		}

		want := filehash.FileHash{Filename: "main/binary-amd64/Packages", Hash: tc.hash, Size: 3}
		if tc.hashes[0] != want {
			t.Errorf("%s list: got %+v, want %+v", tc.name, tc.hashes[0], want)
		}
	}
}
