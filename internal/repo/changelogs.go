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
	"os"
	"path"
	"slices"
	"strings"
	stdtime "time"

	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/deb822/changelog"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/time"
	"oaklab.hu/debian/deb822/types/version"
)

// changelogs publishes the changelogs the Release file advertises, and prunes
// the ones nothing published references any more. It only runs for a
// configuration that asks for changelogs and gives a URL to serve them from.
func (b *build) changelogs() error {
	if !b.conf.HasChangelogs() {
		return nil
	}

	changelogReferences, err := b.writeChangelogs()
	if err != nil {
		return fmt.Errorf("failed to write changelogs: %w", err)
	}

	if err := b.pruneChangelogs(changelogReferences); err != nil {
		return err
	}

	return nil
}

// pruneChangelogs deletes every published changelog file the build did not
// reference.
func (b *build) pruneChangelogs(referenced []string) error {
	if err := fs.WalkDir(b.fsys, changelogsDir, func(changelogFile string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to find changelog files: %w", err)
		}

		if d.IsDir() || !strings.HasSuffix(changelogFile, ".changelog") {
			return nil
		}

		if slices.Contains(referenced, changelogFile) {
			slog.Debug("Changelog file is referenced, skipping removal",
				slog.String("file", changelogFile))

			return nil
		}

		slog.Info("Removing unused changelog file",
			slog.String("file", changelogFile))
		if err := b.fsys.Remove(changelogFile); err != nil {
			return fmt.Errorf("failed to remove unused changelog file: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to prune changelog files: %w", err)
	}

	return nil
}

// changelogsDir is where the Changelogs URL the Release file advertises
// resolves to.
const changelogsDir = "changelogs"

func (b *build) writeChangelogs() ([]string, error) {
	packages := make(map[string]types.Package)
	for releaseComponent, releasePkgs := range b.packages {
		component := strings.Split(releaseComponent, "/")[1]
		for _, pkg := range releasePkgs {
			relPath := changelogPathForPackage(component, &pkg)
			if current, ok := packages[relPath]; ok && !preferChangelogSource(&pkg, &current) {
				continue
			}

			packages[relPath] = pkg
		}
	}

	slog.Info("Updating changelogs", slog.String("dir", changelogsDir))

	if err := b.fsys.MkdirAll(changelogsDir); err != nil {
		return nil, fmt.Errorf("failed to create changelogs directory: %w", err)
	}

	referencedFiles := make([]string, 0, len(packages))
	written := 0
	for relPath, pkg := range packages {
		changelogPath := path.Join(changelogsDir, relPath)
		if _, err := b.fsys.Stat(changelogPath); errors.Is(err, fs.ErrNotExist) {
			slog.Info("Creating changelog file", slog.String("file", changelogPath))

			pkgSource, pkgVer := changelogSource(&pkg)

			changelogData, changelogTime, err := b.packageChangelog(pkg.Filename, pkgSource, pkg.Name)
			if err != nil {
				switch {
				case errors.Is(err, deb.ErrPackageUnreadable):
					slog.Warn("Package file is unreadable, skipping changelog",
						slog.String("package", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("architecture", pkg.Architecture.String()),
						slog.String("error", err.Error()),
					)

					continue
				case errors.Is(err, deb.ErrChangelogSymlink), errors.Is(err, os.ErrNotExist):
					reason := "the package ships none"
					if errors.Is(err, deb.ErrChangelogSymlink) {
						reason = "the documentation directory is a symlink"
					}

					slog.Warn("Generating placeholder changelog",
						slog.String("package", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("architecture", pkg.Architecture.String()),
						slog.String("reason", reason),
					)

					changelogData, err = placeholderChangelog(pkgSource, *pkgVer, pkg.Maintainer, changelogTime)
					if err != nil {
						slog.Warn("Failed to generate placeholder changelog",
							slog.String("package", pkg.Name),
							slog.String("version", pkg.Version.String()),
							slog.String("architecture", pkg.Architecture.String()),
							slog.String("error", err.Error()),
						)

						continue
					}
				default:
					slog.Warn("Failed to get package changelog",
						slog.String("package", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("architecture", pkg.Architecture.String()),
						slog.String("error", err.Error()),
					)

					continue
				}
			}

			if err := b.fsys.MkdirAll(path.Dir(changelogPath)); err != nil {
				return nil, fmt.Errorf("failed to create changelog subdirectory: %w", err)
			}

			// Dated by the archive it came out of rather than by the build, so
			// that a rebuild does not churn a mirror.
			if err := b.fsys.WriteFile(changelogPath, changelogData, 0o644, changelogTime); err != nil {
				return nil, fmt.Errorf("failed to write changelog file: %w", err)
			}

			written++
		}

		referencedFiles = append(referencedFiles, changelogPath)
	}

	if written > 0 {
		slog.Info("Wrote changelogs",
			slog.Int("count", written),
			slog.String("dir", changelogsDir))
	} else {
		slog.Info("No changelogs written, all files already exist")
	}

	slices.Sort(referencedFiles)
	return slices.Compact(referencedFiles), nil
}

// packageChangelog reports the changelog a published package ships, off the
// walk of its payload the Contents stage has usually already paid for.
func (b *build) packageChangelog(poolPath, source, name string) ([]byte, stdtime.Time, error) {
	scan, err := b.scanPool(poolPath)
	if err != nil {
		return nil, stdtime.Time{}, err
	}

	return scan.Changelog(source, name)
}

// placeholderChangelog synthesises the single entry published for a package
// that ships no changelog of its own, so that the Changelogs URL advertised in
// the Release file still resolves to something apt can parse.
func placeholderChangelog(source string, pkgVer version.Version, maintainer string, date stdtime.Time) ([]byte, error) {
	var buf bytes.Buffer

	if err := changelog.NewWriter(&buf).Write(changelog.Entry{
		Source:        source,
		Version:       pkgVer,
		Distributions: []string{"unstable"},
		Urgency:       changelog.DefaultUrgency,
		Changes:       []string{"", "  * No changelog available.", ""},
		Maintainer:    maintainer,
		Date:          time.Time(date),
	}); err != nil {
		return nil, fmt.Errorf("failed to write changelog entry: %w", err)
	}

	return buf.Bytes(), nil
}

// changelogSource is the source package a changelog is filed under and the
// version it is published at. The source version applies only when the Source
// field is what named the package: a Source carrying a version but no name is
// not a rename, and the binary version is then what the changelog is written
// at.
func changelogSource(pkg *types.Package) (string, *version.Version) {
	source := sourceNameOf(pkg)

	if pkg.Source != nil && pkg.Source.Version != nil && source == strings.TrimSpace(pkg.Source.Name) {
		return source, pkg.Source.Version
	}

	return source, &pkg.Version
}

// preferChangelogSource reports whether candidate should provide the changelog
// of a path current already holds. Every binary package of one source maps onto
// the single changelog file of that source, so the winner has to be decided on
// the packages rather than on the order they happened to be read in: the
// package carrying the source's own name ships the changelog, and a -dbgsym,
// whose documentation directory is a symlink, must never shadow it.
func preferChangelogSource(candidate, current *types.Package) bool {
	source, _ := changelogSource(candidate)

	candidateName := strings.TrimSpace(candidate.Name)
	currentName := strings.TrimSpace(current.Name)

	if candidateName == currentName || currentName == source {
		return false
	}
	if candidateName == source {
		return true
	}

	return candidateName < currentName
}

func changelogPathForPackage(componentName string, pkg *types.Package) string {
	pkgSource, pkgVer := changelogSource(pkg)

	return path.Join(componentName, sourcePrefix(pkgSource), pkgSource,
		pkgSource+"_"+pkgVer.StringWithoutEpoch()+".changelog")
}
