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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

	changelogReferences, err := writeChangelogs(b.repoDir, b.packages)
	if err != nil {
		return fmt.Errorf("failed to write changelogs: %w", err)
	}

	if err := pruneChangelogs(b.repoDir, changelogReferences); err != nil {
		return err
	}

	return nil
}

// pruneChangelogs deletes every published changelog file the build did not
// reference.
func pruneChangelogs(repoDir string, referenced []string) error {
	changelogDir := filepath.Join(repoDir, "changelogs")
	if err := filepath.WalkDir(changelogDir, func(changelogFile string, d os.DirEntry, err error) error {
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
		if err := os.Remove(changelogFile); err != nil {
			return fmt.Errorf("failed to remove unused changelog file: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to prune changelog files: %w", err)
	}

	return nil
}

func writeChangelogs(repoDir string, packagesForReleaseComponent map[string][]types.Package) ([]string, error) {
	packages := make(map[string]types.Package)
	for releaseComponent, releasePkgs := range packagesForReleaseComponent {
		component := strings.Split(releaseComponent, "/")[1]
		for _, pkg := range releasePkgs {
			path := changelogPathForPackage(component, &pkg)
			if _, ok := packages[path]; !ok {
				packages[path] = pkg
			}
		}
	}

	dir := filepath.Join(repoDir, "changelogs")
	slog.Info("Updating changelogs", slog.String("dir", dir))

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create changelogs directory: %w", err)
	}

	referencedFiles := make([]string, 0, len(packages))
	written := 0
	for path, pkg := range packages {
		changelogPath := filepath.Join(dir, path)
		if _, err := os.Stat(changelogPath); os.IsNotExist(err) {
			slog.Info("Creating changelog file", slog.String("file", changelogPath))

			pkgSource := ""
			pkgVer := &pkg.Version
			if pkg.Source != nil && pkg.Source.Name != "" {
				pkgSource = pkg.Source.Name
				if pkg.Source.Version != nil {
					pkgVer = pkg.Source.Version
				}
			}
			sourceOrName := pkgSource
			if sourceOrName == "" {
				sourceOrName = strings.TrimSpace(pkg.Name)
			}
			changelogData, changelogTime, err := deb.GetPackageChangelog(sourceOrName, pkg.Name, filepath.Join(repoDir, pkg.Filename))
			if err != nil {
				if !os.IsNotExist(err) {
					slog.Warn("Failed to get package changelog",
						slog.String("package", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("architecture", pkg.Architecture.String()),
						slog.String("error", err.Error()),
					)

					continue
				}

				slog.Warn("Changelog not found, generating dummy changelog",
					slog.String("package", pkg.Name),
					slog.String("version", pkg.Version.String()),
					slog.String("architecture", pkg.Architecture.String()),
				)

				changelogData, err = placeholderChangelog(sourceOrName, *pkgVer, pkg.Maintainer, changelogTime)
				if err != nil {
					slog.Warn("Failed to generate dummy changelog",
						slog.String("package", pkg.Name),
						slog.String("version", pkg.Version.String()),
						slog.String("architecture", pkg.Architecture.String()),
						slog.String("error", err.Error()),
					)

					continue
				}
			}

			if err := os.MkdirAll(filepath.Dir(changelogPath), 0o755); err != nil {
				return nil, fmt.Errorf("failed to create changelog subdirectory: %w", err)
			}

			if err := os.WriteFile(changelogPath, changelogData, 0o644); err != nil {
				return nil, fmt.Errorf("failed to write changelog file: %w", err)
			}

			if err := os.Chtimes(changelogPath, stdtime.Time{}, changelogTime); err != nil {
				return nil, fmt.Errorf("failed to set changelog file modification time: %w", err)
			}

			written++
		}

		referencedFiles = append(referencedFiles, changelogPath)
	}

	if written > 0 {
		slog.Info("Wrote changelogs",
			slog.Int("count", written),
			slog.String("dir", dir))
	} else {
		slog.Info("No changelogs written, all files already exist")
	}

	slices.Sort(referencedFiles)
	return slices.Compact(referencedFiles), nil
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

func changelogPathForPackage(componentName string, pkg *types.Package) string {
	var pkgSource string
	pkgVer := &pkg.Version
	if pkg.Source != nil && pkg.Source.Name != "" {
		pkgSource = pkg.Source.Name
		if pkg.Source.Version != nil {
			pkgVer = pkg.Source.Version
		}
	} else {
		pkgSource = strings.TrimSpace(pkg.Name)
	}

	prefix := pkgSource[:1]
	if strings.HasPrefix(pkgSource, "lib") {
		prefix = pkgSource[:4]
	}

	return filepath.Join(componentName, prefix, pkgSource, pkgSource+"_"+pkgVer.StringWithoutEpoch()+".changelog")
}
