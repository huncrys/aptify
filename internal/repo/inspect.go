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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"oaklab.hu/debian/deb822/types"
)

// Inspect writes every package the repository publishes to w as JSON.
func Inspect(repoDir string, w io.Writer) error {
	if dir, err := os.Stat(repoDir); err != nil || !dir.IsDir() {
		return fmt.Errorf("repository directory does not exist: %s", repoDir)
	}

	files, err := filepath.Glob(filepath.Join(repoDir, "dists", "*", "*", "binary-*", "Packages"))
	if err != nil {
		return fmt.Errorf("failed to find Packages files: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no Packages files found in repository directory: %s", repoDir)
	}

	var packages []types.Package

	for _, file := range files {
		candidates, err := readPackagesFile(file)
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
