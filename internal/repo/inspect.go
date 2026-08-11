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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/types"
)

// Inspect writes every package the repository publishes to w as JSON.
func Inspect(fsys repofs.FS, w io.Writer) error {
	dir, err := fsys.Stat(".")
	if err != nil {
		// Only a repository that is genuinely not there gets the friendly
		// message; the wrong credentials, the wrong region and a bucket that
		// does not exist all have to say what actually went wrong.
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("repository directory does not exist: %s", fsys.Name())
		}

		return fmt.Errorf("failed to read repository %s: %w", fsys.Name(), err)
	}

	if !dir.IsDir() {
		return fmt.Errorf("repository is not a directory: %s", fsys.Name())
	}

	files, err := fsys.Glob(packagesIndiceGlob)
	if err != nil {
		return fmt.Errorf("failed to find Packages files: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no Packages files found in repository directory: %s", fsys.Name())
	}

	var packages []types.Package

	for _, file := range files {
		candidates, err := readPackagesFile(fsys, file)
		if err != nil {
			return err
		}

		for _, candidate := range candidates {
			found := slices.ContainsFunc(packages, func(pkg types.Package) bool {
				return candidate.Compare(pkg) == 0
			})

			if !found {
				packages = append(packages, candidate)
			}
		}
	}

	if err := json.NewEncoder(w).Encode(packages); err != nil {
		return fmt.Errorf("failed to encode packages: %w", err)
	}

	return nil
}
