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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
	"oaklab.hu/debian/deb822/types/boolean"
)

// writePackagesIndice writes every published variant of the Packages indice,
// reporting whether any of them changed.
func writePackagesIndice(archDir string, packages []types.Package) (bool, error) {
	slog.Info("Writing Packages indice",
		slog.String("dir", archDir), slog.Int("count", len(packages)))

	var packageList bytes.Buffer
	if err := deb822.Marshal(&packageList, packages); err != nil {
		return false, fmt.Errorf("failed to marshal packages: %w", err)
	}

	var changed bool
	for _, name := range []string{"Packages", "Packages.gz", "Packages.xz"} {
		fileChanged, err := writeIndiceFile(filepath.Join(archDir, name), packageList.Bytes())
		if err != nil {
			return changed, fmt.Errorf("failed to write Packages file: %w", err)
		}

		changed = changed || fileChanged
	}

	return changed, nil
}

// writeComponentReleaseFile publishes the per component, per architecture
// Release stub apt reads alongside the indices in the directory. It is
// rendered and compared on every build rather than gated on the incremental
// skip logic, so a repository published before the stub existed heals itself.
func writeComponentReleaseFile(archDir string, releaseConf v1alpha1.ReleaseConfig, component, architecture string, byHash bool) (bool, error) {
	// Archive names the suite the directory belongs to; a release that does
	// not configure one is only ever addressed by its codename.
	archive := releaseConf.Suite
	if archive == "" {
		archive = releaseConf.Name
	}

	stub := types.ComponentRelease{
		Archive:      archive,
		Origin:       releaseConf.Origin,
		Label:        releaseConf.Label,
		Version:      releaseConf.Version,
		Component:    component,
		Architecture: arch.MustParse(architecture),
	}

	if byHash {
		acquireByHash := boolean.Boolean(true)
		stub.AcquireByHash = &acquireByHash
	}

	var body bytes.Buffer
	if err := deb822.Marshal(&body, stub); err != nil {
		return false, fmt.Errorf("failed to marshal component release: %w", err)
	}

	path := filepath.Join(archDir, "Release")
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, body.Bytes()) {
		return false, nil
	}

	slog.Info("Writing component Release file", slog.String("dir", archDir))

	if err := writeFileAtomic(path, body.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("failed to write component Release file: %w", err)
	}

	return true, nil
}

// removeArchIndices deletes every indice published for an architecture,
// reporting whether there was anything left to delete.
func removeArchIndices(componentDir, arch string) (bool, error) {
	paths := []string{filepath.Join(componentDir, "binary-"+arch)}
	for _, name := range contentsIndiceNames(arch) {
		paths = append(paths, filepath.Join(componentDir, name))
	}

	var removed bool
	for _, path := range paths {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return removed, fmt.Errorf("failed to stat stale indice: %w", err)
		}

		slog.Info("Removing stale indice", slog.String("path", path))

		if err := os.RemoveAll(path); err != nil {
			return removed, fmt.Errorf("failed to remove stale indice: %w", err)
		}

		removed = true
	}

	return removed, nil
}
