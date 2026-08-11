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

package repo

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dpeckett/uncompr"
)

// writeIndiceFile writes body to path, compressed according to the path's
// extension, reporting whether the published bytes changed. A file whose
// contents are already correct is left alone, so that a mirror does not see
// its mtime churn.
func writeIndiceFile(path string, body []byte) (bool, error) {
	var published bytes.Buffer

	w, err := uncompr.NewWriter(&published, path)
	if err != nil {
		return false, fmt.Errorf("failed to create compression writer: %w", err)
	}

	if _, err := w.Write(body); err != nil {
		_ = w.Close()

		return false, fmt.Errorf("failed to compress file: %w", err)
	}

	// Flush the compressor explicitly, so a failed flush is reported rather
	// than silently truncating the indice.
	if err := w.Close(); err != nil {
		return false, fmt.Errorf("failed to close compression writer: %w", err)
	}

	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, published.Bytes()) {
		return false, nil
	}

	if err := writeFileAtomic(path, published.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("failed to write file: %w", err)
	}

	return true, nil
}

// writeFileAtomic writes body through a temporary in the same directory and
// renames it into place. The published file may be hard linked from the
// by-hash tree, where rewriting it in place would silently change the contents
// served under its old checksum; the temporary is dot prefixed so that a
// crashed build cannot leave behind something the Release globs would match
// and sign.
func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)

	f, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := f.Name()

	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(body); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}
	tmpPath = ""

	return nil
}
