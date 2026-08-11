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
	"strings"

	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
)

// loadExisting reads back what the repository directory already publishes.
// This is what makes builds incremental: every dists/*/*/binary-*/Packages is
// decoded into the package list of its release/component, there is no database.
func (b *build) loadExisting() error {
	if dir, err := os.Stat(b.repoDir); err == nil && dir.IsDir() {
		slog.Info("Loading existing repository", slog.String("dir", b.repoDir))

		if paths, err := filepath.Glob(filepath.Join(b.repoDir, "dists", "*", "*", "binary-*", "Packages")); err == nil {
			for _, packagesFile := range paths {
				parts := strings.FieldsFunc(packagesFile, func(c rune) bool { return os.PathSeparator == c })
				releaseComponent := strings.Join(parts[len(parts)-4:len(parts)-2], "/")
				slog.Debug("Found existing Packages file",
					slog.String("file", packagesFile),
					slog.String("release_component", releaseComponent))

				if _, ok := b.archs[releaseComponent]; !ok {
					b.archs[releaseComponent] = make(map[string]bool)
				}

				packages, err := readPackagesFile(packagesFile)
				if err != nil {
					return err
				}

				b.packages[releaseComponent] = append(b.packages[releaseComponent], packages...)

				// Get the architectures from the Packages file.
				for _, pkg := range packages {
					b.candidates[pkg.Filename] = true
					b.archs[releaseComponent][pkg.Architecture.String()] = true
				}
			}
		}

		// Deduplicate b.packages
		for releaseComponent, packages := range b.packages {
			uniquePackages := make([]types.Package, 0, len(packages))
			for _, pkg := range packages {
				if !slices.ContainsFunc(uniquePackages, func(existingPkg types.Package) bool {
					return pkg.Compare(existingPkg) == 0
				}) {
					if b.reread {
						pkgPath := filepath.Join(b.repoDir, pkg.Filename)
						if freshPkg, err := deb.GetMetadata(pkgPath); err != nil {
							return fmt.Errorf("failed to reread package metadata: %w", err)
						} else {
							// The control file carries none of the checksums
							// of the package file itself, so they have to be
							// carried across rather than blanked.
							freshPkg.MD5sum = pkg.MD5sum
							freshPkg.SHA1 = pkg.SHA1
							freshPkg.SHA256 = pkg.SHA256
							freshPkg.Filename = pkg.Filename
							freshPkg.Size = pkg.Size
							pkg = *freshPkg
						}
					}
					uniquePackages = append(uniquePackages, pkg)
				}
			}
			b.packages[releaseComponent] = uniquePackages
		}
	}

	return nil
}

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
