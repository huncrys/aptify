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

package deb

import (
	"errors"
	"fmt"
	"io/fs"
)

// GetPackageContents lists the files shipped by the package named by fsys and
// name, which is what a Contents indice describes it by.
func GetPackageContents(fsys fs.FS, name string) ([]string, error) {
	scan, err := ScanPackage(fsys, name)
	if err != nil {
		var unreadable *unreadableError
		if errors.As(err, &unreadable) {
			return nil, fmt.Errorf("failed to open package file: %w", unreadable.err)
		}

		return nil, err
	}

	return scan.Contents, nil
}
