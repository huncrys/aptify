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
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	cp "github.com/otiai10/copy"
	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/deb822/types"
)

// ingest expands the configured globs, reads the metadata of every .deb they
// match and copies it into the pool. A package already published with a
// matching SHA256 is skipped; a mismatch warns and overwrites.
func (b *build) ingest() error {
	// Copy packages to the pool directory.
	for _, releaseConf := range b.conf.Releases {
		for _, componentConf := range releaseConf.Components {
			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)

			for _, pattern := range componentConf.Packages {
				matches, err := filepath.Glob(pattern)
				if err != nil {
					return fmt.Errorf("failed to find deb files for %s: %w", pattern, err)
				}

				for _, pkgPath := range matches {
					pkg, err := deb.GetMetadata(pkgPath)
					if err != nil {
						return fmt.Errorf("failed to get package metadata: %w", err)
					}

					sums, err := hashsum.File(pkgPath)
					if err != nil {
						return fmt.Errorf("failed to hash package: %w", err)
					}
					pkg.MD5sum = sums.MD5
					pkg.SHA1 = sums.SHA1
					pkg.SHA256 = sums.SHA256

					skip := false
					if _, ok := b.packages[releaseComponent]; ok {
						for _, existingPkg := range b.packages[releaseComponent] {
							if pkg.Compare(existingPkg) != 0 {
								continue
							}
							if existingPkg.SHA256 != pkg.SHA256 {
								slog.Warn("Package SHA256 mismatch, overwriting",
									slog.String("name", pkg.Name),
									slog.String("version", pkg.Version.String()),
									slog.String("architecture", pkg.Architecture.String()),
									slog.String("existing_sha256", existingPkg.SHA256),
									slog.String("new_sha256", pkg.SHA256))
								continue
							}
							skip = true
							break
						}
					}

					if skip {
						slog.Info("Skipping existing package",
							slog.String("name", pkg.Name),
							slog.String("version", pkg.Version.String()),
							slog.String("architecture", pkg.Architecture.String()))

						continue
					}

					// Remove duplicates
					b.packages[releaseComponent] = slices.DeleteFunc(b.packages[releaseComponent], func(existingPkg types.Package) bool {
						return pkg.Compare(existingPkg) == 0
					})

					if _, ok := b.archs[releaseComponent]; !ok {
						b.archs[releaseComponent] = make(map[string]bool)
					}
					b.archs[releaseComponent][pkg.Architecture.String()] = true

					// Only copy each deb file once.
					// Use the component name from the first release that includes the package.
					if existingPoolPath, ok := b.poolPaths[pkgPath]; !ok {
						pkg.Filename = poolPathForPackage(componentConf.Name, pkg)

						if err := os.MkdirAll(filepath.Dir(filepath.Join(b.repoDir, pkg.Filename)), 0o755); err != nil {
							return fmt.Errorf("failed to create pool subdirectory: %w", err)
						}

						if err := cp.Copy(pkgPath, filepath.Join(b.repoDir, pkg.Filename), cp.Options{PreserveTimes: true}); err != nil {
							return fmt.Errorf("failed to copy package: %w", err)
						}

						b.poolPaths[pkgPath] = pkg.Filename
					} else {
						pkg.Filename = existingPoolPath
					}
					b.candidates[pkg.Filename] = true

					// Get the size of the package file.
					fi, err := os.Stat(filepath.Join(b.repoDir, pkg.Filename))
					if err != nil {
						return fmt.Errorf("failed to get package size: %w", err)
					}
					pkg.Size = int(fi.Size())

					b.packages[releaseComponent] = append(b.packages[releaseComponent], *pkg)
					b.added[releaseComponent] = append(b.added[releaseComponent], *pkg)
				}
			}
		}
	}

	return nil
}
