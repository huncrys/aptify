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
	"path"
	"path/filepath"
	"slices"

	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
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
					if err := b.ingestPackage(releaseComponent, componentConf.Name, pkgPath); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// ingestPackage reads one local .deb, copies it into the pool of a component
// and records it as published there. It is what the configured globs expand to,
// and what a one-off add names directly.
func (b *build) ingestPackage(releaseComponent, componentName, pkgPath string) error {
	pkg, err := deb.GetMetadata(repofs.LocalFile(pkgPath))
	if err != nil {
		return fmt.Errorf("failed to get package metadata: %w", err)
	}

	sums, err := hashsum.File(repofs.LocalFile(pkgPath))
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

		return nil
	}

	// Remove duplicates
	b.packages[releaseComponent] = slices.DeleteFunc(b.packages[releaseComponent], func(existingPkg types.Package) bool {
		return pkg.Compare(existingPkg) == 0
	})

	if _, ok := b.archs[releaseComponent]; !ok {
		b.archs[releaseComponent] = make(map[string]bool)
	}
	b.archs[releaseComponent][pkg.Architecture.String()] = true

	// The pool copy is byte for byte the file that was just hashed, so its size
	// is read here rather than by statting the copy back.
	fi, err := os.Stat(pkgPath)
	if err != nil {
		return fmt.Errorf("failed to get package size: %w", err)
	}
	pkg.Size = int(fi.Size())

	// Only copy each deb file once.
	// Use the component name from the first release that includes the package.
	if existingPoolPath, ok := b.poolPaths[pkgPath]; !ok {
		pkg.Filename = poolPathForPackage(componentName, pkg)

		if err := b.fsys.MkdirAll(path.Dir(pkg.Filename)); err != nil {
			return fmt.Errorf("failed to create pool subdirectory: %w", err)
		}

		if err := b.copyToPool(pkgPath, pkg.Filename, fi); err != nil {
			return err
		}

		b.poolPaths[pkgPath] = pkg.Filename
	} else {
		pkg.Filename = existingPoolPath
	}
	b.candidates[pkg.Filename] = true
	b.sourcePaths[pkg.Filename] = pkgPath

	b.packages[releaseComponent] = append(b.packages[releaseComponent], *pkg)
	b.added[releaseComponent] = append(b.added[releaseComponent], *pkg)

	return nil
}

// copyToPool publishes a source .deb under its pool path, keeping the source
// file's modification time so that re-running a build does not churn a
// mirrored pool.
func (b *build) copyToPool(sourcePath, poolPath string, fi os.FileInfo) error {
	f, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open package: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := b.fsys.WriteFrom(poolPath, f, fi.Size(), fi.ModTime()); err != nil {
		return fmt.Errorf("failed to copy package: %w", err)
	}

	return nil
}
