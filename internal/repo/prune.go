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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/deb822/types"
)

// surplusVersions returns the versions of one package that fall outside
// maxVersions, given its versions by architecture. Architecture `all` packages
// are folded into every architecture's indices, so they are judged as a client
// sees them: they compete with each architecture's own versions, and one is
// only surplus once it is surplus for every architecture that publishes it.
// Keeping it for one architecture can leave another over maxVersions, which is
// the honest outcome - there is a single entry to keep or drop, not one per
// architecture.
func surplusVersions(versionsForArch map[string][]types.Package, maxVersions int) []types.Package {
	architectures := slices.Sorted(maps.Keys(versionsForArch))

	// With nothing to fold them into, `all` packages are published as an
	// architecture of their own and compete only with each other.
	if len(architectures) > 1 {
		architectures = slices.DeleteFunc(architectures, func(architecture string) bool {
			return architecture == archAll.String()
		})
	}

	// How many architectures each version is published for, and in how many of
	// them it is surplus.
	published := make(map[string]int)
	surplus := make(map[string]int)

	var candidates []types.Package

	for _, architecture := range architectures {
		versions := slices.Clone(versionsForArch[architecture])
		if architecture != archAll.String() {
			versions = append(versions, versionsForArch[archAll.String()]...)
		}

		slices.SortStableFunc(versions, func(a, b types.Package) int {
			return a.Compare(b)
		})

		countMustRemove := max(len(versions)-maxVersions, 0)

		for i, pkg := range versions {
			key := pkg.Version.String() + "/" + pkg.Architecture.String()

			if published[key] == 0 {
				candidates = append(candidates, pkg)
			}
			published[key]++

			if i < countMustRemove {
				surplus[key]++
			}
		}
	}

	var removals []types.Package
	for _, pkg := range candidates {
		key := pkg.Version.String() + "/" + pkg.Architecture.String()
		if surplus[key] == published[key] {
			removals = append(removals, pkg)
		}
	}

	return removals
}

// backfillPackageDigests fills the fields older builds did not publish -
// Description-md5 from the description itself, MD5sum and SHA1 by re-reading
// the pool - and reports the release/components whose Packages indices have to
// be rewritten as a result. The ingest keeps the stanza it already has for a
// package whose file is unchanged, so this is the only route by which an
// existing repository gains the fields.
func backfillPackageDigests(repoDir string, packagesForReleaseComponent map[string][]types.Package) (map[string]bool, error) {
	backfilled := make(map[string]bool)

	// A pool file is shared by every component listing the package, so it is
	// only ever hashed once.
	sumsForPoolPath := make(map[string]hashsum.Sums)

	for _, releaseComponent := range slices.Sorted(maps.Keys(packagesForReleaseComponent)) {
		packages := packagesForReleaseComponent[releaseComponent]

		for i := range packages {
			pkg := &packages[i]

			if descriptionMD5 := pkg.DescriptionMD5Sum(); descriptionMD5 != pkg.DescriptionMD5 {
				pkg.DescriptionMD5 = descriptionMD5
				backfilled[releaseComponent] = true
			}

			if pkg.MD5sum != "" && pkg.SHA1 != "" {
				continue
			}

			sums, ok := sumsForPoolPath[pkg.Filename]
			if !ok {
				var err error
				sums, err = hashsum.File(filepath.Join(repoDir, pkg.Filename))
				if errors.Is(err, os.ErrNotExist) {
					// A repository missing a pool file builds today, so this
					// stays a warning: the stanza keeps the checksums it has.
					slog.Warn("Package file missing from pool, leaving its checksums as published",
						slog.String("name", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("filename", pkg.Filename))

					continue
				} else if err != nil {
					return nil, fmt.Errorf("failed to hash pool file %s: %w", pkg.Filename, err)
				}

				sumsForPoolPath[pkg.Filename] = sums
			}

			pkg.MD5sum = sums.MD5
			pkg.SHA1 = sums.SHA1
			backfilled[releaseComponent] = true
		}
	}

	return backfilled, nil
}
