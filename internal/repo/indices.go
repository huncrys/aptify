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
	"slices"
	"sort"
	"strings"

	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
	"oaklab.hu/debian/deb822/types/boolean"
)

// writeIndices publishes the indices of every release, component and
// architecture, then the release files that name them.
func (b *build) writeIndices() error {
	// Create release files.
	for _, releaseConf := range b.conf.Releases {
		var architectures []arch.Arch

		modified := false

		for _, componentConf := range releaseConf.Components {
			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)
			componentDir := filepath.Join(b.repoDir, "dists", releaseConf.Name, componentConf.Name)

			// Architecture `all` packages go into every architecture's indices,
			// so a separate `all` architecture only duplicates them. Earlier
			// versions published one, and apt keeps fetching it for as long as
			// the release advertises the architecture, so drop it here. It is
			// kept when there is nothing to fold it into, as the component
			// would otherwise have no indices at all.
			componentArchs := b.archs[releaseComponent]

			migrated := false
			if len(componentArchs) > 1 && componentArchs[archAll.String()] {
				delete(componentArchs, archAll.String())

				var err error
				migrated, err = removeArchIndices(componentDir, archAll.String())
				if err != nil {
					return err
				}

				// The release no longer publishes the indices it listed.
				modified = modified || migrated
			}

			for architecture := range componentArchs {
				architectures = append(architectures, arch.MustParse(architecture))

				archDir := filepath.Join(componentDir, "binary-"+architecture)

				if err := os.MkdirAll(archDir, 0o755); err != nil {
					return fmt.Errorf("failed to create dists subdirectory: %w", err)
				}

				// The stub is rendered and compared on every build rather than
				// gated on the incremental skip below, so a repository
				// published before it existed heals itself.
				stubWritten, err := writeComponentReleaseFile(archDir, releaseConf,
					componentConf.Name, architecture, b.conf.ByHashEnabled())
				if err != nil {
					return fmt.Errorf("failed to write component Release file: %w", err)
				}
				modified = modified || stubWritten

				packages := filterForArch(b.packages[releaseComponent], architecture)
				newPackages := filterForArch(b.added[releaseComponent], architecture)
				removedPackages := filterForArch(b.removed[releaseComponent], architecture)

				// Whatever the dropped `all` indices held has to be folded in
				// here, so a migrated component is rewritten from its full
				// package list rather than incrementally.
				writePackages := b.force || b.reread || migrated ||
					b.backfilled[releaseComponent] ||
					len(newPackages) > 0 || len(removedPackages) > 0

				// A repository built before the uncompressed Contents indice
				// was published has to be rewritten even when nothing changed,
				// otherwise apt never acquires Contents at all.
				writeContents := writePackages ||
					!contentsIndiceComplete(componentDir, architecture)

				if !writePackages && !writeContents {
					slog.Info("Skipping index generation, no new or removed packages found",
						slog.String("dir", archDir),
					)

					continue
				}

				sort.Slice(packages, func(i, j int) bool {
					return packages[i].Compare(packages[j]) < 0
				})
				sort.Slice(newPackages, func(i, j int) bool {
					return newPackages[i].Compare(newPackages[j]) < 0
				})
				sort.Slice(removedPackages, func(i, j int) bool {
					return removedPackages[i].Compare(removedPackages[j]) < 0
				})

				if writePackages {
					changed, err := writePackagesIndice(archDir, packages)
					if err != nil {
						return fmt.Errorf("failed to write package lists: %w", err)
					}
					modified = modified || changed
				} else {
					slog.Info("Skipping Packages indice generation, no new or removed packages found",
						slog.String("dir", archDir),
					)
				}

				if !writeContents {
					slog.Info("Skipping Contents file generation, no new packages found",
						slog.String("dir", archDir),
					)

					continue
				}

				changed, err := writeContentsIndice(b.repoDir, componentDir, architecture,
					packages, newPackages, removedPackages, b.reread)
				if err != nil {
					return fmt.Errorf("failed to write Contents file: %w", err)
				}
				modified = modified || changed
			}
		}

		// Every component contributes its own architectures, so a release with
		// more than one component names most of them repeatedly.
		slices.SortFunc(architectures, func(a, b arch.Arch) int {
			return strings.Compare(a.String(), b.String())
		})
		architectures = slices.Compact(architectures)

		releaseDir := filepath.Join(b.repoDir, "dists", releaseConf.Name)

		if err := os.MkdirAll(releaseDir, 0o755); err != nil {
			return fmt.Errorf("failed to create release directory: %w", err)
		}

		if err := writeReleaseFile(releaseDir, modified, b.conf, releaseConf, architectures, b.privateKey); err != nil {
			return fmt.Errorf("failed to write release: %w", err)
		}
	}

	return nil
}

// filterForArch narrows a package list to what an architecture's indices
// publish: its own packages, plus the architecture `all` ones folded into every
// architecture.
func filterForArch(pkgs []types.Package, architecture string) []types.Package {
	filtered := make([]types.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Architecture.Is(archAll) || pkg.Architecture.String() == architecture {
			filtered = append(filtered, pkg)
		}
	}

	return filtered
}

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
