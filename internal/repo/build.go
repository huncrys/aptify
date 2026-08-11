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
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	cp "github.com/otiai10/copy"
	"oaklab.hu/debian/aptify/internal/config"
	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/keys"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
)

// Options is everything a repository build is given: where the repository
// lives, the configuration describing it, the key it is signed with, and the
// two switches that override the incremental skips.
type Options struct {
	RepoDir        string
	ConfigPath     string
	PrivateKeyPath string
	Force          bool
	Reread         bool
}

// Build publishes the repository the configuration describes.
func Build(opts Options) error {
	repoDir := opts.RepoDir
	confPath := opts.ConfigPath
	privateKeyPath := opts.PrivateKeyPath
	force := opts.Force
	reread := opts.Reread

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key not found; run 'aptify init-keys' to generate one")
	}

	privateKey, err := keys.Load(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	confFile, err := os.Open(confPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer confFile.Close()

	conf, err := config.FromYAML(confFile)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	packagesForReleaseComponent := make(map[string][]types.Package)
	newPackagesForReleaseComponent := make(map[string][]types.Package)
	removedPackagesForReleaseComponent := make(map[string][]types.Package)
	archsForReleaseComponent := make(map[string]map[string]bool)
	pkgPoolPaths := make(map[string]string)
	poolCandidates := make(map[string]bool)

	// Load existing repository directory
	if dir, err := os.Stat(repoDir); err == nil && dir.IsDir() {
		slog.Info("Loading existing repository", slog.String("dir", repoDir))

		if paths, err := filepath.Glob(filepath.Join(repoDir, "dists", "*", "*", "binary-*", "Packages")); err == nil {
			for _, packagesFile := range paths {
				parts := strings.FieldsFunc(packagesFile, func(c rune) bool { return os.PathSeparator == c })
				releaseComponent := strings.Join(parts[len(parts)-4:len(parts)-2], "/")
				slog.Debug("Found existing Packages file",
					slog.String("file", packagesFile),
					slog.String("release_component", releaseComponent))

				if _, ok := archsForReleaseComponent[releaseComponent]; !ok {
					archsForReleaseComponent[releaseComponent] = make(map[string]bool)
				}

				packages, err := readPackagesFile(packagesFile)
				if err != nil {
					return err
				}

				packagesForReleaseComponent[releaseComponent] = append(packagesForReleaseComponent[releaseComponent], packages...)

				// Get the architectures from the Packages file.
				for _, pkg := range packages {
					poolCandidates[pkg.Filename] = true
					archsForReleaseComponent[releaseComponent][pkg.Architecture.String()] = true
				}
			}
		}

		// Deduplicate packagesForReleaseComponent
		for releaseComponent, packages := range packagesForReleaseComponent {
			uniquePackages := make([]types.Package, 0, len(packages))
			for _, pkg := range packages {
				if !slices.ContainsFunc(uniquePackages, func(existingPkg types.Package) bool {
					return pkg.Compare(existingPkg) == 0
				}) {
					if reread {
						pkgPath := filepath.Join(repoDir, pkg.Filename)
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
			packagesForReleaseComponent[releaseComponent] = uniquePackages
		}
	}

	// Copy packages to the pool directory.
	for _, releaseConf := range conf.Releases {
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
					if _, ok := packagesForReleaseComponent[releaseComponent]; ok {
						for _, existingPkg := range packagesForReleaseComponent[releaseComponent] {
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
					packagesForReleaseComponent[releaseComponent] = slices.DeleteFunc(packagesForReleaseComponent[releaseComponent], func(existingPkg types.Package) bool {
						return pkg.Compare(existingPkg) == 0
					})

					if _, ok := archsForReleaseComponent[releaseComponent]; !ok {
						archsForReleaseComponent[releaseComponent] = make(map[string]bool)
					}
					archsForReleaseComponent[releaseComponent][pkg.Architecture.String()] = true

					// Only copy each deb file once.
					// Use the component name from the first release that includes the package.
					if existingPoolPath, ok := pkgPoolPaths[pkgPath]; !ok {
						pkg.Filename = poolPathForPackage(componentConf.Name, pkg)

						if err := os.MkdirAll(filepath.Dir(filepath.Join(repoDir, pkg.Filename)), 0o755); err != nil {
							return fmt.Errorf("failed to create pool subdirectory: %w", err)
						}

						if err := cp.Copy(pkgPath, filepath.Join(repoDir, pkg.Filename), cp.Options{PreserveTimes: true}); err != nil {
							return fmt.Errorf("failed to copy package: %w", err)
						}

						pkgPoolPaths[pkgPath] = pkg.Filename
					} else {
						pkg.Filename = existingPoolPath
					}
					poolCandidates[pkg.Filename] = true

					// Get the size of the package file.
					fi, err := os.Stat(filepath.Join(repoDir, pkg.Filename))
					if err != nil {
						return fmt.Errorf("failed to get package size: %w", err)
					}
					pkg.Size = int(fi.Size())

					packagesForReleaseComponent[releaseComponent] = append(packagesForReleaseComponent[releaseComponent], *pkg)
					newPackagesForReleaseComponent[releaseComponent] = append(newPackagesForReleaseComponent[releaseComponent], *pkg)
				}
			}
		}
	}

	for _, releaseConf := range conf.Releases {
		for _, componentConf := range releaseConf.Components {
			if componentConf.MaxVersions == 0 {
				continue
			}

			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)

			// The versions of every package, by name and then architecture.
			versions := make(map[string]map[string][]types.Package)
			for _, pkg := range packagesForReleaseComponent[releaseComponent] {
				architecture := pkg.Architecture.String()

				if versions[pkg.Name] == nil {
					versions[pkg.Name] = make(map[string][]types.Package)
				}

				if !slices.ContainsFunc(versions[pkg.Name][architecture], func(existingPkg types.Package) bool {
					return pkg.Compare(existingPkg) == 0
				}) {
					versions[pkg.Name][architecture] = append(versions[pkg.Name][architecture], pkg)
				}
			}

			for _, name := range slices.Sorted(maps.Keys(versions)) {
				for _, pkgToRemove := range surplusVersions(versions[name], int(componentConf.MaxVersions)) {
					slog.Info("Removing old package version",
						slog.String("name", pkgToRemove.Name),
						slog.String("architecture", pkgToRemove.Architecture.String()),
						slog.String("version", pkgToRemove.Version.String()),
						slog.String("filename", pkgToRemove.Filename),
					)

					comparator := func(a types.Package) bool {
						return a.Compare(pkgToRemove) == 0
					}
					packagesForReleaseComponent[releaseComponent] = slices.DeleteFunc(packagesForReleaseComponent[releaseComponent], comparator)
					newPackagesForReleaseComponent[releaseComponent] = slices.DeleteFunc(newPackagesForReleaseComponent[releaseComponent], comparator)

					removedPackagesForReleaseComponent[releaseComponent] = append(removedPackagesForReleaseComponent[releaseComponent], pkgToRemove)
				}
			}
		}
	}

	// Fill in the fields older builds did not publish. This runs after the
	// prune so no pool file about to be deleted is hashed, and after the
	// ingest so every Filename resolves.
	backfilled, err := backfillPackageDigests(repoDir, packagesForReleaseComponent)
	if err != nil {
		return fmt.Errorf("failed to backfill package digests: %w", err)
	}

	// Create release files.
	for _, releaseConf := range conf.Releases {
		var architectures []arch.Arch

		modified := false

		for _, componentConf := range releaseConf.Components {
			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)
			componentDir := filepath.Join(repoDir, "dists", releaseConf.Name, componentConf.Name)

			// Architecture `all` packages go into every architecture's indices,
			// so a separate `all` architecture only duplicates them. Earlier
			// versions published one, and apt keeps fetching it for as long as
			// the release advertises the architecture, so drop it here. It is
			// kept when there is nothing to fold it into, as the component
			// would otherwise have no indices at all.
			componentArchs := archsForReleaseComponent[releaseComponent]

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
					componentConf.Name, architecture, conf.ByHashEnabled())
				if err != nil {
					return fmt.Errorf("failed to write component Release file: %w", err)
				}
				modified = modified || stubWritten

				packages := packagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredPackages := make([]types.Package, 0, len(packages))
				for _, pkg := range packages {
					if pkg.Architecture.Is(archAll) || pkg.Architecture.String() == architecture {
						filteredPackages = append(filteredPackages, pkg)
					}
				}
				packages = filteredPackages

				newPackages := newPackagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredNewPackages := make([]types.Package, 0, len(newPackages))
				for _, pkg := range newPackages {
					if pkg.Architecture.Is(archAll) || pkg.Architecture.String() == architecture {
						filteredNewPackages = append(filteredNewPackages, pkg)
					}
				}
				newPackages = filteredNewPackages

				removedPackages := removedPackagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredRemovedPackages := make([]types.Package, 0, len(removedPackages))
				for _, pkg := range removedPackages {
					if pkg.Architecture.Is(archAll) || pkg.Architecture.String() == architecture {
						filteredRemovedPackages = append(filteredRemovedPackages, pkg)
					}
				}
				removedPackages = filteredRemovedPackages

				// Whatever the dropped `all` indices held has to be folded in
				// here, so a migrated component is rewritten from its full
				// package list rather than incrementally.
				writePackages := force || reread || migrated ||
					backfilled[releaseComponent] ||
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

				changed, err := writeContentsIndice(repoDir, componentDir, architecture,
					packages, newPackages, removedPackages, reread)
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

		releaseDir := filepath.Join(repoDir, "dists", releaseConf.Name)

		if err := os.MkdirAll(releaseDir, 0o755); err != nil {
			return fmt.Errorf("failed to create release directory: %w", err)
		}

		if err := writeReleaseFile(releaseDir, modified, conf, releaseConf, architectures, privateKey); err != nil {
			return fmt.Errorf("failed to write release: %w", err)
		}
	}

	// Count the pool paths the indices ended up referencing. Counting as
	// packages are read and prune, rather than from the result, miscounts every
	// package that is listed more than once per component - an architecture
	// `all` package is in every architecture's indice, so removing it once left
	// its file behind as permanently referenced.
	poolReferences := make(map[string]int)
	for _, packages := range packagesForReleaseComponent {
		for _, pkg := range packages {
			poolReferences[pkg.Filename]++
		}
	}

	for poolPath := range poolCandidates {
		if poolReferences[poolPath] > 0 {
			continue
		}

		slog.Info("Removing unused file from pool",
			slog.String("file", poolPath))
		if err := os.Remove(filepath.Join(repoDir, poolPath)); err != nil {
			return fmt.Errorf("failed to remove unused package file: %w", err)
		}
	}

	if conf.HasChangelogs() {
		changelogReferences, err := writeChangelogs(repoDir, packagesForReleaseComponent)
		if err != nil {
			return fmt.Errorf("failed to write changelogs: %w", err)
		}

		changelogDir := filepath.Join(repoDir, "changelogs")
		if err := filepath.WalkDir(changelogDir, func(changelogFile string, d os.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("failed to find changelog files: %w", err)
			}

			if d.IsDir() || !strings.HasSuffix(changelogFile, ".changelog") {
				return nil
			}

			if slices.Contains(changelogReferences, changelogFile) {
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
	}

	// Save a copy of the signing key.
	signingKeyFilePath := filepath.Join(repoDir, "signing_key.asc")
	if _, err = os.Stat(signingKeyFilePath); err == nil {

		if signingKeyFile, err := os.Open(signingKeyFilePath); err == nil {
			defer signingKeyFile.Close()

			if keyRing, err := openpgp.ReadArmoredKeyRing(signingKeyFile); err == nil {
				for _, publicKey := range keyRing {
					if slices.Equal(publicKey.PrimaryKey.Fingerprint, privateKey.PrimaryKey.Fingerprint) {
						slog.Info("Skipping writing signing key, no changes",
							slog.String("file", signingKeyFilePath))
						return nil
					}
				}
			}
		}

		slog.Info("Signing key file does not match private key, overwriting",
			slog.String("file", signingKeyFilePath))
	}

	slog.Info("Writing signing key file", slog.String("file", signingKeyFilePath))

	signingKeyFile, err := os.Create(filepath.Join(repoDir, "signing_key.asc"))
	if err != nil {
		return fmt.Errorf("failed to create signing key file: %w", err)
	}
	defer signingKeyFile.Close()

	if err := keys.WritePublic(signingKeyFile, privateKey); err != nil {
		return err
	}

	if stat, err := os.Stat(privateKeyPath); err == nil {
		if err := os.Chtimes(signingKeyFilePath, stdtime.Time{}, stat.ModTime()); err != nil {
			return fmt.Errorf("failed to set signing key file modification time: %w", err)
		}
	}

	return nil
}
