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
	"io/fs"
	"log/slog"
	"path"
	"slices"
	"sort"
	"strings"
	stdtime "time"

	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
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

		releaseDir := path.Join("dists", releaseConf.Name)

		// The checksums of every indice this build published, keyed the way a
		// Release file names them: relative to the release directory. They are
		// what spares the release assembly a second read of each index.
		published := make(map[string]hashsum.Sums)
		collect := func(sums ...hashsum.Sums) {
			for _, s := range sums {
				s.Path = relativeName(releaseDir, s.Path)
				published[s.Path] = s
			}
		}

		for _, componentConf := range releaseConf.Components {
			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)
			componentDir := path.Join("dists", releaseConf.Name, componentConf.Name)

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
				migrated, err = removeArchIndices(b.fsys, componentDir, archAll.String())
				if err != nil {
					return err
				}

				// The release no longer publishes the indices it listed.
				modified = modified || migrated
			}

			for architecture := range componentArchs {
				architectures = append(architectures, arch.MustParse(architecture))

				archDir := path.Join(componentDir, "binary-"+architecture)

				if err := b.fsys.MkdirAll(archDir); err != nil {
					return fmt.Errorf("failed to create dists subdirectory: %w", err)
				}

				// The stub is rendered and compared on every build rather than
				// gated on the incremental skip below, so a repository
				// published before it existed heals itself.
				stubSums, stubWritten, err := writeComponentReleaseFile(b.fsys, archDir, releaseConf,
					componentConf.Name, architecture, b.conf.ByHashEnabled())
				if err != nil {
					return fmt.Errorf("failed to write component Release file: %w", err)
				}
				modified = modified || stubWritten
				collect(stubSums)

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
					!contentsIndiceComplete(b.fsys, componentDir, architecture)

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
					sums, changed, err := writePackagesIndice(b.fsys, archDir, packages)
					if err != nil {
						return fmt.Errorf("failed to write package lists: %w", err)
					}
					modified = modified || changed
					collect(sums...)
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

				sums, changed, err := b.writeContentsIndice(componentDir, architecture,
					packages, newPackages, removedPackages)
				if err != nil {
					return fmt.Errorf("failed to write Contents file: %w", err)
				}
				modified = modified || changed
				collect(sums...)
			}
		}

		// Every component contributes its own architectures, so a release with
		// more than one component names most of them repeatedly.
		slices.SortFunc(architectures, func(a, b arch.Arch) int {
			return strings.Compare(a.String(), b.String())
		})
		architectures = slices.Compact(architectures)

		if err := b.fsys.MkdirAll(releaseDir); err != nil {
			return fmt.Errorf("failed to create release directory: %w", err)
		}

		if err := b.writeReleaseFile(releaseDir, releaseConf, architectures, modified, published); err != nil {
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
// reporting their checksums and whether any of them changed.
func writePackagesIndice(fsys repofs.FS, archDir string, packages []types.Package) ([]hashsum.Sums, bool, error) {
	slog.Info("Writing Packages indice",
		slog.String("dir", archDir), slog.Int("count", len(packages)))

	var packageList bytes.Buffer
	if err := deb822.Marshal(&packageList, packages); err != nil {
		return nil, false, fmt.Errorf("failed to marshal packages: %w", err)
	}

	var (
		sums    []hashsum.Sums
		changed bool
	)

	for _, name := range []string{"Packages", "Packages.gz", "Packages.xz"} {
		fileSums, fileChanged, err := writeIndiceFile(fsys, path.Join(archDir, name), packageList.Bytes())
		if err != nil {
			return sums, changed, fmt.Errorf("failed to write Packages file: %w", err)
		}

		sums = append(sums, fileSums)
		changed = changed || fileChanged
	}

	return sums, changed, nil
}

// writeComponentReleaseFile publishes the per component, per architecture
// Release stub apt reads alongside the indices in the directory. It is
// rendered and compared on every build rather than gated on the incremental
// skip logic, so a repository published before the stub existed heals itself.
func writeComponentReleaseFile(fsys repofs.FS, archDir string, releaseConf v1alpha1.ReleaseConfig, component, architecture string, byHash bool) (hashsum.Sums, bool, error) {
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
		return hashsum.Sums{}, false, fmt.Errorf("failed to marshal component release: %w", err)
	}

	name := path.Join(archDir, "Release")
	if existing, err := fs.ReadFile(fsys, name); err == nil && bytes.Equal(existing, body.Bytes()) {
		return hashsum.Bytes(name, existing), false, nil
	}

	slog.Info("Writing component Release file", slog.String("dir", archDir))

	if err := fsys.WriteFile(name, body.Bytes(), 0o644, stdtime.Time{}); err != nil {
		return hashsum.Sums{}, false, fmt.Errorf("failed to write component Release file: %w", err)
	}

	return hashsum.Bytes(name, body.Bytes()), true, nil
}

// removeArchIndices deletes every indice published for an architecture,
// reporting whether there was anything left to delete.
func removeArchIndices(fsys repofs.FS, componentDir, arch string) (bool, error) {
	names := []string{path.Join(componentDir, "binary-"+arch)}
	for _, name := range contentsIndiceNames(arch) {
		names = append(names, path.Join(componentDir, name))
	}

	var removed bool
	for _, name := range names {
		if _, err := fsys.Stat(name); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return removed, fmt.Errorf("failed to stat stale indice: %w", err)
		}

		slog.Info("Removing stale indice", slog.String("path", name))

		if err := fsys.RemoveAll(name); err != nil {
			return removed, fmt.Errorf("failed to remove stale indice: %w", err)
		}

		removed = true
	}

	return removed, nil
}
