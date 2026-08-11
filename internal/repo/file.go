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
	"io/fs"
	stdtime "time"

	"github.com/dpeckett/uncompr"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// writeIndiceFile writes body to name, compressed according to the name's
// extension, reporting whether the published bytes changed. A file whose
// contents are already correct is left alone, so that a mirror does not see
// its mtime churn.
func writeIndiceFile(fsys repofs.FS, name string, body []byte) (bool, error) {
	var published bytes.Buffer

	w, err := uncompr.NewWriter(&published, name)
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

	if existing, err := fs.ReadFile(fsys, name); err == nil && bytes.Equal(existing, published.Bytes()) {
		return false, nil
	}

	if err := fsys.WriteFile(name, published.Bytes(), 0o644, stdtime.Time{}); err != nil {
		return false, fmt.Errorf("failed to write file: %w", err)
	}

	return true, nil
}
