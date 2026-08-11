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

// TestFile pins the digests against published test vectors, so that no
// algorithm can quietly end up describing something else.
func TestFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "abc"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}

	sums, err := File(os.DirFS(dir), "abc")
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

// TestBytes checks that hashing a body in memory and reading the same body
// back off a file describe it identically: an index is published by the first
// and verified by the second.
func TestBytes(t *testing.T) {
	dir := t.TempDir()

	body := []byte("Package: hello-world\n")
	if err := os.WriteFile(filepath.Join(dir, "Packages"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	fromFile, err := File(os.DirFS(dir), "Packages")
	if err != nil {
		t.Fatal(err)
	}

	if got := Bytes("Packages", body); got != fromFile {
		t.Errorf("got %+v, want %+v", got, fromFile)
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
