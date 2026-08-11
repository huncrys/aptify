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
	"bytes"
	"os"
	"path/filepath"
	"testing"
	stdtime "time"

	"oaklab.hu/debian/aptify/internal/repofs"
)

// TestWriteIndiceFileUnchanged covers the two things a mirror and the by-hash
// tree depend on: an indice whose bytes are already correct is not written at
// all, so its mtime does not churn, and a rewrite replaces the file rather
// than its contents, so a by-hash entry linking the old bytes keeps them.
func TestWriteIndiceFileUnchanged(t *testing.T) {
	for _, name := range []string{"Packages", "Packages.gz", "Packages.xz"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			fsys := repofs.NewOS(dir)
			path := filepath.Join(dir, name)

			body := []byte("Package: hello-world\n")

			changed, err := writeIndiceFile(fsys, name, body)
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Error("first write reported no change")
			}

			// A by-hash entry is a hard link to the published indice.
			link := filepath.Join(dir, "by-hash-entry")
			if err := os.Link(path, link); err != nil {
				t.Fatal(err)
			}

			published, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			// Backdate the indice, so that any write at all is visible.
			modTime := stdtime.Now().Add(-30 * 24 * stdtime.Hour).Truncate(stdtime.Second)
			if err := os.Chtimes(path, stdtime.Time{}, modTime); err != nil {
				t.Fatal(err)
			}

			changed, err = writeIndiceFile(fsys, name, body)
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				t.Error("rewriting the same body reported a change")
			}

			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.ModTime().Equal(modTime) {
				t.Errorf("modification time: got %s, want %s", fi.ModTime(), modTime)
			}

			changed, err = writeIndiceFile(fsys, name, []byte("Package: hello-world\nVersion: 2.0\n"))
			if err != nil {
				t.Fatal(err)
			}
			if !changed {
				t.Error("rewriting a different body reported no change")
			}

			rewritten, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(rewritten, published) {
				t.Error("the indice was not rewritten")
			}

			// The link still holds what it was published as, which is what a
			// client asking for the old checksum gets.
			linked, err := os.ReadFile(link)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(linked, published) {
				t.Error("the hard linked copy was rewritten under its old checksum")
			}
		})
	}
}

// TestWriteIndiceFileLeavesNoTemporaries checks that the temporaries a write
// goes through are cleaned up, and that a Release glob would not have matched
// them anyway.
func TestWriteIndiceFileLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()

	if _, err := writeIndiceFile(repofs.NewOS(dir), "Packages", []byte("Package: hello-world\n")); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != "Packages" {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}

		t.Errorf("directory contents: got %q, want [Packages]", names)
	}
}
