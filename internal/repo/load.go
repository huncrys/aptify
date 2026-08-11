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
	"fmt"
	"os"

	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
)

// readPackagesFile decodes a single Packages indice, closing the file before
// returning so that a caller iterating over many of them does not accumulate
// open handles.
func readPackagesFile(path string) ([]types.Package, error) {
	reader, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Packages file: %w", err)
	}
	defer reader.Close()

	decoder, err := deb822.NewDecoder(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for Packages file: %w", err)
	}

	var packages []types.Package
	if err := decoder.Decode(&packages); err != nil {
		return nil, fmt.Errorf("failed to decode Packages file: %w", err)
	}

	return packages, nil
}
