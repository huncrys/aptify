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

package sha256sum

import (
	"fmt"
	"os"
	"path/filepath"

	"oaklab.hu/debian/deb822/types/filehash"
)

// Directory returns the sha256sum of all files in a directory.
func Directory(dir string, globs []string) ([]filehash.FileHash, error) {
	var hashes []filehash.FileHash
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of directory: %w", err)
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		matched := len(globs) == 0
		if !matched {
			for _, glob := range globs {
				if ok, _ := filepath.Match(filepath.Join(dir, glob), path); ok {
					matched = true
					break
				}
			}
		}

		if !matched {
			return nil
		}

		sum, err := File(path)
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		hashes = append(hashes, filehash.FileHash{
			Filename: relativePath,
			Hash:     sum,
			Size:     fi.Size(),
		})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return hashes, nil
}
