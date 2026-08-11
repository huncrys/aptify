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

package main

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/adrg/xdg"
	"github.com/dpeckett/uncompr"
	cp "github.com/otiai10/copy"
	"github.com/urfave/cli/v3"
	"oaklab.hu/debian/aptify/internal/config"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/constants"
	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/util"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/changelog"
	"oaklab.hu/debian/deb822/contents"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
	"oaklab.hu/debian/deb822/types/boolean"
	"oaklab.hu/debian/deb822/types/filehash"
	"oaklab.hu/debian/deb822/types/list"
	"oaklab.hu/debian/deb822/types/time"
	"oaklab.hu/debian/deb822/types/version"
)

func main() {
	defaultConfDir, err := xdg.ConfigFile("aptify")
	if err != nil {
		panic(fmt.Errorf("failed to get default config dir: %w", err))
	}

	initLogger := func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: (*slog.Level)(cmd.Value("log-level").(*util.LevelFlag)),
		})))

		return ctx, nil
	}

	initConfDir := func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		confDir := cmd.String("config-dir")
		if confDir == "" {
			return ctx, fmt.Errorf("no configuration directory specified")
		}

		if err := os.MkdirAll(confDir, 0o700); err != nil {
			return ctx, fmt.Errorf("failed to create configuration directory: %w", err)
		}

		return ctx, nil
	}

	cmd := &cli.Command{
		Name:    "aptify",
		Usage:   "Create apt repositories from Debian packages",
		Version: constants.Version,
		Commands: []*cli.Command{
			{
				Name:  "init-keys",
				Usage: "Generate a new GPG key pair for signing releases",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "name",
						Usage: "Name of the key owner",
					},
					&cli.StringFlag{
						Name:  "comment",
						Usage: "Comment to add to the key",
					},
					&cli.StringFlag{
						Name:  "email",
						Usage: "Email address of the key owner",
					},
				},
				Before: util.BeforeAll(initLogger, initConfDir),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					entityConfig := &packet.Config{
						RSABits: 4096,
						Time:    stdtime.Now,
					}

					slog.Info("Generating RSA key")

					// Create a new entity.
					entity, err := openpgp.NewEntity(cmd.String("name"), cmd.String("comment"), cmd.String("email"), entityConfig)
					if err != nil {
						return fmt.Errorf("failed to create entity: %w", err)
					}

					slog.Info("Saving key pair", slog.String("dir", cmd.String("config-dir")))

					// Serialize the private key.
					var privateKey bytes.Buffer
					privateKeyWriter, err := armor.Encode(&privateKey, openpgp.PrivateKeyType, nil)
					if err != nil {
						return fmt.Errorf("failed to encode private key: %w", err)
					}
					if err := entity.SerializePrivate(privateKeyWriter, nil); err != nil {
						return fmt.Errorf("failed to serialize private key: %w", err)
					}
					if err := privateKeyWriter.Close(); err != nil {
						return fmt.Errorf("failed to close private key writer: %w", err)
					}

					confDir := cmd.String("config-dir")

					// Write private key to file.
					if err := os.WriteFile(filepath.Join(confDir, "aptify_private.asc"), privateKey.Bytes(), 0o600); err != nil {
						return fmt.Errorf("failed to write private key: %w", err)
					}

					return nil
				},
			},
			{
				Name:  "build",
				Usage: "Build a Debian repository from a configuration file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "config",
						Aliases:  []string{"c"},
						Usage:    "Configuration file",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "repository-dir",
						Aliases: []string{"d"},
						Usage:   "Directory to store the repository",
						Value:   "repository",
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"f"},
						Usage:   "Force rebuild of all indices, even if no changes are detected",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:    "reread",
						Aliases: []string{"r"},
						Usage:   "Re-read all package files",
						Value:   false,
					},
				},
				Before: util.BeforeAll(initLogger, initConfDir),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					repoDir := cmd.String("repository-dir")

					slog.Info("Building repository", slog.String("dir", repoDir))

					privateKeyPath := filepath.Join(cmd.String("config-dir"), "aptify_private.asc")

					return buildRepository(
						repoDir,
						cmd.String("config"),
						privateKeyPath,
						cmd.Bool("force"),
						cmd.Bool("reread"),
					)
				},
			},
			{
				Name:  "inspect",
				Usage: "Dump all packages in the repository as JSON",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "repository-dir",
						Aliases: []string{"d"},
						Usage:   "Directory containing the repository",
						Value:   "repository",
					},
				},
				Before: util.BeforeAll(initLogger),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					repoDir := cmd.String("repository-dir")

					return inspectRepository(repoDir)
				},
			},
		},
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:    "log-level",
				Sources: cli.EnvVars("LOG_LEVEL"),
				Usage:   "Set the log verbosity level",
				Value:   util.FromSlogLevel(slog.LevelInfo),
			},
			&cli.StringFlag{
				Name:    "config-dir",
				Sources: cli.EnvVars("CONFIG_DIR"),
				Usage:   "Directory to store configuration",
				Value:   defaultConfDir,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		slog.Error("Error", slog.Any("error", err))
		os.Exit(1)
	}
}

// archAll is the architecture whose packages belong in every architecture's
// indices rather than in one of its own.
var archAll = new(arch.MustParse("all"))

// releaseIndiceGlobs selects the files a Release file publishes checksums for,
// relative to the release directory. Anything apt has to verify has to be
// matched here or it is signed for but unlisted. The patterns are deliberately
// narrow: `*/binary-*/*` would also match the by-hash entries, which are hard
// links to files already listed under their own names.
var releaseIndiceGlobs = []string{"*/binary-*/Packages*", "*/binary-*/Release", "*/Contents-*"}

func buildRepository(repoDir, confPath, privateKeyPath string, force, reread bool) error {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key not found; run 'aptify init-keys' to generate one")
	}

	privateKey, err := loadPrivateKey(privateKeyPath)
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

	publicKeyWriter, err := armor.Encode(signingKeyFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	if err := privateKey.Serialize(publicKeyWriter); err != nil {
		return fmt.Errorf("failed to serialize public key: %w", err)
	}

	if err := publicKeyWriter.Close(); err != nil {
		return fmt.Errorf("failed to close public key writer: %w", err)
	}

	if stat, err := os.Stat(privateKeyPath); err == nil {
		if err := os.Chtimes(signingKeyFilePath, stdtime.Time{}, stat.ModTime()); err != nil {
			return fmt.Errorf("failed to set signing key file modification time: %w", err)
		}
	}

	return nil
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

// latestPackages picks the newest version of each package name.
func latestPackages(packages []types.Package) map[string]types.Package {
	latest := make(map[string]types.Package, len(packages))
	for _, pkg := range packages {
		if existing, ok := latest[pkg.Name]; ok && existing.Compare(pkg) >= 0 {
			continue
		}

		latest[pkg.Name] = pkg
	}

	return latest
}

// contentsIndiceComplete reports whether every published variant of the
// Contents indice for an architecture is already on disk.
func contentsIndiceComplete(componentDir, arch string) bool {
	for _, name := range contentsIndiceNames(arch) {
		if _, err := os.Stat(filepath.Join(componentDir, name)); err != nil {
			return false
		}
	}

	return true
}

// contentsIndiceNames returns the file names the Contents indice for an
// architecture is published under. apt resolves the indice by its uncompressed
// name in the Release file and only then picks a compressed variant to fetch,
// so an indice listed as Contents-<arch>.gz alone is never acquired.
func contentsIndiceNames(arch string) []string {
	return []string{
		fmt.Sprintf("Contents-%s", arch),
		fmt.Sprintf("Contents-%s.gz", arch),
	}
}

// writeContentsIndice rewrites the Contents indice for an architecture,
// reporting whether any published variant changed. packages is everything the
// architecture publishes, newPackages and removedPackages what this build
// added and dropped; reread forces every package to be read back from the pool
// rather than only those whose published contents can have changed.
func writeContentsIndice(repoDir, componentDir, arch string, packages, newPackages, removedPackages []types.Package, reread bool) (bool, error) {
	contentsPath := filepath.Join(componentDir, fmt.Sprintf("Contents-%s.gz", arch))

	// Paths shipped by each qualified package name, seeded with whatever the
	// existing indice holds for the packages we are not rewriting.
	packageFiles, err := readContentsIndice(contentsPath)
	if err != nil {
		return false, err
	}

	// Contents has no version column, so a name can be described only once.
	// Describe the version a client would install: the newest one published
	// for this architecture, architecture `all` packages included.
	published := latestPackages(packages)

	// Drop whatever the indice still holds for names the architecture no
	// longer publishes at all.
	maps.DeleteFunc(packageFiles, func(qualifiedName string, _ []string) bool {
		_, ok := published[contents.ParseQualifiedName(qualifiedName).Name]
		return !ok
	})

	described := make(map[string]bool, len(packageFiles))
	for qualifiedName := range packageFiles {
		described[contents.ParseQualifiedName(qualifiedName).Name] = true
	}

	latestNew := latestPackages(newPackages)
	latestRemoved := latestPackages(removedPackages)

	slog.Info("Collecting package contents", slog.String("dir", componentDir))

	for _, name := range slices.Sorted(maps.Keys(published)) {
		pkg := published[name]

		// The indice describes whichever version was newest last time, so it
		// only goes stale when this build published a newer version or
		// removed the very one it described.
		stale := reread || !described[name]
		if added, ok := latestNew[name]; ok && added.Compare(pkg) == 0 {
			stale = true
		}
		if dropped, ok := latestRemoved[name]; ok && dropped.Compare(pkg) > 0 {
			stale = true
		}

		if !stale {
			continue
		}

		pkgContents, err := deb.GetPackageContents(filepath.Join(repoDir, pkg.Filename))
		if err != nil {
			return false, fmt.Errorf("failed to get package contents: %w %s", err, filepath.Join(repoDir, pkg.Filename))
		}

		// Drop the package's previous entries, whatever section it was filed
		// under back then.
		maps.DeleteFunc(packageFiles, func(qualifiedName string, _ []string) bool {
			return contents.ParseQualifiedName(qualifiedName).Name == name
		})

		qualifiedPackageName := pkg.Name
		if pkg.Section != "" {
			qualifiedPackageName = fmt.Sprintf("%s/%s", pkg.Section, pkg.Name)
		}

		packageFiles[qualifiedPackageName] = pkgContents
	}

	// Invert into the layout of the file itself: one line per path, naming
	// every package that ships it.
	pathPackages := make(map[string][]string)
	for pkg, paths := range packageFiles {
		for _, path := range paths {
			if !slices.Contains(pathPackages[path], pkg) {
				pathPackages[path] = append(pathPackages[path], pkg)
			}
		}
	}

	paths := slices.Sorted(maps.Keys(pathPackages))

	slog.Info("Writing Contents indice",
		slog.String("dir", componentDir), slog.Int("count", len(paths)))

	var contentsList bytes.Buffer

	cw := contents.NewWriter(&contentsList)
	for _, path := range paths {
		packages := pathPackages[path]
		sort.Strings(packages)

		if err := cw.Write(contents.Entry{Path: path, Packages: packages}); err != nil {
			return false, fmt.Errorf("failed to write contents: %w", err)
		}
	}

	var changed bool
	for _, name := range contentsIndiceNames(arch) {
		fileChanged, err := writeIndiceFile(filepath.Join(componentDir, name), contentsList.Bytes())
		if err != nil {
			return changed, fmt.Errorf("failed to write Contents file: %w", err)
		}

		changed = changed || fileChanged
	}

	return changed, nil
}

// writeIndiceFile writes body to path, compressed according to the path's
// extension, reporting whether the published bytes changed. A file whose
// contents are already correct is left alone, so that a mirror does not see
// its mtime churn.
func writeIndiceFile(path string, body []byte) (bool, error) {
	var published bytes.Buffer

	w, err := uncompr.NewWriter(&published, path)
	if err != nil {
		return false, fmt.Errorf("failed to create compression writer: %w", err)
	}

	if _, err := w.Write(body); err != nil {
		_ = w.Close()

		return false, fmt.Errorf("failed to compress file: %w", err)
	}

	// Flush the compressor explicitly, so a failed flush is reported rather
	// than silently truncating the indice.
	if err := w.Close(); err != nil {
		return false, fmt.Errorf("failed to close compression writer: %w", err)
	}

	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, published.Bytes()) {
		return false, nil
	}

	if err := writeFileAtomic(path, published.Bytes(), 0o644); err != nil {
		return false, fmt.Errorf("failed to write file: %w", err)
	}

	return true, nil
}

// writeFileAtomic writes body through a temporary in the same directory and
// renames it into place. The published file may be hard linked from the
// by-hash tree, where rewriting it in place would silently change the contents
// served under its old checksum; the temporary is dot prefixed so that a
// crashed build cannot leave behind something the Release globs would match
// and sign.
func writeFileAtomic(path string, body []byte, perm os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)

	f, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := f.Name()

	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(body); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}
	tmpPath = ""

	return nil
}

// readContentsIndice reads an existing Contents indice into the set of paths
// shipped by each qualified package name. A missing indice is not an error.
func readContentsIndice(contentsPath string) (map[string][]string, error) {
	packageFiles := make(map[string][]string)

	f, err := os.Open(contentsPath)
	if errors.Is(err, os.ErrNotExist) {
		return packageFiles, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to open Contents file: %w", err)
	}
	defer f.Close()

	r, err := uncompr.NewReader(f)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// A previous run left an empty file behind.
			return packageFiles, nil
		}

		return nil, fmt.Errorf("failed to create decompression reader: %w", err)
	}
	defer r.Close()

	cr := contents.NewReader(r)
	for {
		entry, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read Contents file: %w", err)
		}

		for _, pkg := range entry.Packages {
			if !slices.Contains(packageFiles[pkg], entry.Path) {
				packageFiles[pkg] = append(packageFiles[pkg], entry.Path)
			}
		}
	}

	return packageFiles, nil
}

func readReleaseFile(releaseDir string, privateKey *openpgp.Entity) (*types.Release, error) {
	releaseFile, err := os.Open(filepath.Join(releaseDir, "InRelease"))
	if err != nil {
		return nil, fmt.Errorf("failed to open Release file: %w", err)
	}
	defer releaseFile.Close()

	decoder, err := deb822.NewDecoder(releaseFile, openpgp.EntityList{privateKey})
	if err != nil {
		return nil, fmt.Errorf("failed to create decoder for Release file: %w", err)
	}

	var release types.Release
	if err := decoder.Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode Release file: %w", err)
	}

	return &release, nil
}

func writeReleaseFile(releaseDir string, modified bool, conf *v1alpha1.Repository, releaseConf v1alpha1.ReleaseConfig, architectures []arch.Arch, privateKey *openpgp.Entity) error {
	var components []string
	for _, component := range releaseConf.Components {
		components = append(components, component.Name)
	}

	changelogs := "no"
	if conf.HasChangelogs() {
		changelogs = fmt.Sprintf("%s/changelogs/@CHANGEPATH@.changelog", conf.URL)
	}

	slices.SortFunc(architectures, func(a, b arch.Arch) int {
		return strings.Compare(a.String(), b.String())
	})

	slices.Sort(components)

	byHash := conf.ByHashEnabled()

	r := types.Release{
		Origin:                      releaseConf.Origin,
		Label:                       releaseConf.Label,
		Suite:                       releaseConf.Suite,
		Version:                     releaseConf.Version,
		Codename:                    releaseConf.Name,
		Changelogs:                  changelogs,
		Date:                        time.Time(stdtime.Now().UTC()),
		Architectures:               list.SpaceDelimited[arch.Arch](architectures),
		Components:                  list.SpaceDelimited[string](components),
		Description:                 releaseConf.Description,
		NoSupportForArchitectureAll: noSupportForArchitectureAll(architectures),
	}

	if byHash {
		acquireByHash := boolean.Boolean(true)
		r.AcquireByHash = &acquireByHash
	}

	// The existing release is both the change oracle and the record of the
	// previous by-hash generation, so it is kept rather than only compared.
	existing, err := readReleaseFile(releaseDir, privateKey)
	if err != nil {
		// Nothing to compare against, and nothing published for a client to be
		// holding: the release has to be written whatever the indices did.
		modified = true
	} else {
		slices.SortFunc(existing.Architectures, func(a, b arch.Arch) int {
			return strings.Compare(a.String(), b.String())
		})

		slices.Sort(existing.Components)

		modified = modified || existing.Origin != r.Origin ||
			existing.Label != r.Label ||
			existing.Suite != r.Suite ||
			existing.Version != r.Version ||
			existing.Codename != r.Codename ||
			existing.Changelogs != r.Changelogs ||
			!slices.Equal(existing.Architectures, r.Architectures) ||
			!slices.Equal(existing.Components, r.Components) ||
			existing.Description != r.Description ||
			existing.NoSupportForArchitectureAll != r.NoSupportForArchitectureAll ||
			!equalAcquireByHash(existing.AcquireByHash, r.AcquireByHash) ||
			// An older build published SHA256 alone.
			len(existing.MD5Sum) == 0 || len(existing.SHA1) == 0 || len(existing.SHA256) == 0
	}

	previous := map[string]map[string]bool{}
	if existing != nil {
		previous = byHashSetsFromRelease(existing)
	}

	// A by-hash entry the live release names has to be on disk, or a client
	// that read it fetches a 404. Statting is enough; nothing is hashed.
	if byHash && !modified {
		modified = !byHashComplete(releaseDir, previous)
	}

	if !modified {
		slog.Info("Skipping release generation, no changes", slog.String("dir", releaseDir))

		if byHash {
			// Nothing was superseded, but entries retired by an earlier build
			// still age out.
			return pruneByHash(releaseDir, previous, previous, conf.ByHashRetention())
		}

		return nil
	}

	slog.Info("Writing Release file", slog.String("dir", releaseDir))

	sums, err := hashsum.Directory(releaseDir, releaseIndiceGlobs)
	if err != nil {
		return fmt.Errorf("failed to hash release: %w", err)
	}

	r.MD5Sum = hashsum.MD5List(sums)
	r.SHA1 = hashsum.SHA1List(sums)
	r.SHA256 = hashsum.SHA256List(sums)

	current := map[string]map[string]bool{}
	if byHash {
		current = byHashSets(sums)

		// Publish the tree before the release advertises it, so that
		// Acquire-By-Hash is never live over an incomplete tree.
		if err := linkByHash(releaseDir, sums); err != nil {
			return fmt.Errorf("failed to publish by-hash indices: %w", err)
		}
	}

	// One rendering of the stanza for all three files, so they cannot disagree.
	var body bytes.Buffer
	if err := deb822.Marshal(&body, r); err != nil {
		return fmt.Errorf("failed to encode release: %w", err)
	}

	if err := writeFileAtomic(filepath.Join(releaseDir, "Release"), body.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write Release file: %w", err)
	}

	var detachedSignature bytes.Buffer
	// Pin the signature to the primary key, which is what the clearsigned
	// InRelease is made with; a detached signature would otherwise prefer a
	// signing subkey and the two would be made by different keys.
	if err := openpgp.ArmoredDetachSign(&detachedSignature, privateKey, bytes.NewReader(body.Bytes()), &packet.Config{
		SigningKeyId: privateKey.PrimaryKey.KeyId,
		DefaultHash:  crypto.SHA256,
	}); err != nil {
		return fmt.Errorf("failed to sign Release file: %w", err)
	}

	if err := writeFileAtomic(filepath.Join(releaseDir, "Release.gpg"), detachedSignature.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write Release signature: %w", err)
	}

	var inRelease bytes.Buffer
	clearsignWriter, err := clearsign.Encode(&inRelease, privateKey.PrivateKey, nil)
	if err != nil {
		return fmt.Errorf("failed to create clearsign writer: %w", err)
	}

	if _, err := clearsignWriter.Write(body.Bytes()); err != nil {
		_ = clearsignWriter.Close()

		return fmt.Errorf("failed to clearsign release: %w", err)
	}

	if err := clearsignWriter.Close(); err != nil {
		return fmt.Errorf("failed to close clearsign writer: %w", err)
	}

	// InRelease is written last: it is the file apt prefers, so it is what
	// makes the new generation live.
	if err := writeFileAtomic(filepath.Join(releaseDir, "InRelease"), inRelease.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write InRelease file: %w", err)
	}

	if !byHash {
		// The flag is gone from the release just published, so the tree it
		// described can go too. Never the other way round.
		return removeByHash(releaseDir)
	}

	return pruneByHash(releaseDir, current, previous, conf.ByHashRetention())
}

// noSupportForArchitectureAll returns the value of the Release field of the
// same name for a release publishing these architectures. Architecture `all`
// packages are normally folded into every architecture's indices, which is
// exactly what the field tells apt; a component with nothing to fold them into
// still publishes binary-all, and the field would then tell apt to ignore
// indices the release does list.
func noSupportForArchitectureAll(architectures []arch.Arch) string {
	if slices.ContainsFunc(architectures, func(a arch.Arch) bool { return a.Is(archAll) }) {
		return ""
	}

	return "Packages"
}

func equalAcquireByHash(a, b *boolean.Boolean) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

// byHashDir is the directory an index's by-hash entries for one algorithm are
// published in, relative to the release directory and slash separated.
func byHashDir(indicePath, algorithm string) string {
	return path.Join(path.Dir(indicePath), hashsum.ByHashDirName, algorithm)
}

// byHashSets maps each by-hash directory to the set of entries these checksums
// call for.
func byHashSets(sums []hashsum.Sums) map[string]map[string]bool {
	sets := make(map[string]map[string]bool)

	for _, s := range sums {
		for _, digest := range s.Digests() {
			dir := byHashDir(s.Path, digest.Algorithm)
			if sets[dir] == nil {
				sets[dir] = make(map[string]bool)
			}

			sets[dir][digest.Hash] = true
		}
	}

	return sets
}

// byHashSetsFromRelease maps each by-hash directory to the set of entries a
// release file names, which is what a client holding it can still ask for.
func byHashSetsFromRelease(r *types.Release) map[string]map[string]bool {
	sets := make(map[string]map[string]bool)

	for algorithm, hashes := range map[string]list.NewLineDelimited[filehash.FileHash]{
		"MD5Sum": r.MD5Sum,
		"SHA1":   r.SHA1,
		"SHA256": r.SHA256,
	} {
		for _, hash := range hashes {
			dir := byHashDir(hash.Filename, algorithm)
			if sets[dir] == nil {
				sets[dir] = make(map[string]bool)
			}

			sets[dir][hash.Hash] = true
		}
	}

	return sets
}

// byHashComplete reports whether every entry of the sets is on disk.
func byHashComplete(releaseDir string, sets map[string]map[string]bool) bool {
	for dir, hashes := range sets {
		for hash := range hashes {
			if _, err := os.Stat(filepath.Join(releaseDir, filepath.FromSlash(dir), hash)); err != nil {
				slog.Info("Republishing release, by-hash entry is missing",
					slog.String("entry", path.Join(dir, hash)))

				return false
			}
		}
	}

	return true
}

// linkByHash publishes every checksum of every index as a hard link to the
// index itself, so that a client which read a release can still fetch what it
// names after a later build has replaced the index. One inode holds the
// content however many names point at it.
func linkByHash(releaseDir string, sums []hashsum.Sums) error {
	for _, s := range sums {
		indicePath := filepath.Join(releaseDir, filepath.FromSlash(s.Path))

		for _, digest := range s.Digests() {
			dir := filepath.Join(releaseDir, filepath.FromSlash(byHashDir(s.Path, digest.Algorithm)))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create by-hash directory: %w", err)
			}

			entryPath := filepath.Join(dir, digest.Hash)
			if _, err := os.Stat(entryPath); err == nil {
				// The name is the digest of the content, so an entry that is
				// already there holds exactly these bytes.
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to stat by-hash entry: %w", err)
			}

			if err := os.Link(indicePath, entryPath); err != nil {
				return fmt.Errorf("failed to link by-hash entry: %w", err)
			}
		}
	}

	return nil
}

// pruneByHash retires superseded by-hash entries. An entry the previous
// release named but this one does not has just gone stale, so its clock is
// started here: a hard link's mtime is when its content was created, not when
// it stopped being current, and an age sweep over that would delete the
// predecessor of an index that had sat unchanged for a month the moment it
// changed. Entries named by neither release are removed once they are older
// than the retention window.
func pruneByHash(releaseDir string, current, previous map[string]map[string]bool, retention stdtime.Duration) error {
	now := stdtime.Now()

	err := filepath.WalkDir(releaseDir, func(dirPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() || d.Name() != hashsum.ByHashDirName {
			return nil
		}

		algorithms, err := os.ReadDir(dirPath)
		if err != nil {
			return err
		}

		for _, algorithm := range algorithms {
			if !algorithm.IsDir() {
				continue
			}

			algorithmDir := filepath.Join(dirPath, algorithm.Name())

			relativeDir, err := filepath.Rel(releaseDir, algorithmDir)
			if err != nil {
				return err
			}
			key := filepath.ToSlash(relativeDir)

			entries, err := os.ReadDir(algorithmDir)
			if err != nil {
				return err
			}

			for _, entry := range entries {
				if entry.IsDir() || current[key][entry.Name()] {
					continue
				}

				entryPath := filepath.Join(algorithmDir, entry.Name())

				if previous[key][entry.Name()] {
					// Superseded by this build: start its retention window now.
					if err := os.Chtimes(entryPath, stdtime.Time{}, now); err != nil {
						return fmt.Errorf("failed to touch superseded by-hash entry: %w", err)
					}

					continue
				}

				info, err := entry.Info()
				if err != nil {
					return err
				}

				if now.Sub(info.ModTime()) < retention {
					continue
				}

				slog.Info("Removing expired by-hash entry",
					slog.String("entry", path.Join(key, entry.Name())))

				if err := os.Remove(entryPath); err != nil {
					return fmt.Errorf("failed to remove expired by-hash entry: %w", err)
				}
			}
		}

		return fs.SkipDir
	})
	if err != nil {
		return fmt.Errorf("failed to prune by-hash entries: %w", err)
	}

	return nil
}

// removeByHash deletes every by-hash tree under a release, which is what
// turning the feature off has to do once the release no longer advertises it.
func removeByHash(releaseDir string) error {
	err := filepath.WalkDir(releaseDir, func(dirPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() || d.Name() != hashsum.ByHashDirName {
			return nil
		}

		slog.Info("Removing by-hash directory", slog.String("dir", dirPath))

		if err := os.RemoveAll(dirPath); err != nil {
			return fmt.Errorf("failed to remove by-hash directory: %w", err)
		}

		return fs.SkipDir
	})
	if err != nil {
		return fmt.Errorf("failed to remove by-hash directories: %w", err)
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

func poolPathForPackage(componentName string, pkg *types.Package) string {
	pkgName := strings.TrimSpace(pkg.Name)
	var source string
	if pkg.Source != nil && pkg.Source.Name != "" {
		source = pkg.Source.Name
	} else {
		source = pkgName
	}

	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		prefix = source[:4]
	}

	return filepath.Join("pool", componentName, prefix, source,
		fmt.Sprintf("%s_%s_%s.deb", pkgName, pkg.Version, pkg.Architecture))
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

func loadPrivateKey(path string) (*openpgp.Entity, error) {
	keyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key: %w", err)
	}
	defer keyFile.Close()

	keyRing, err := openpgp.ReadArmoredKeyRing(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read armored key ring: %w", err)
	}

	return keyRing[0], nil
}

func inspectRepository(repoDir string) error {
	if dir, err := os.Stat(repoDir); err != nil || !dir.IsDir() {
		return fmt.Errorf("repository directory does not exist: %s", repoDir)
	}

	files, err := filepath.Glob(filepath.Join(repoDir, "dists", "*", "*", "binary-*", "Packages"))
	if err != nil {
		return fmt.Errorf("failed to find Packages files: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no Packages files found in repository directory: %s", repoDir)
	}

	var packages []types.Package

	for _, file := range files {
		candidates, err := readPackagesFile(file)
		if err != nil {
			return err
		}

		for _, candidate := range candidates {
			found := slices.ContainsFunc(packages, func(pkg types.Package) bool {
				return candidate.Compare(pkg) == 0
			})

			if !found {
				packages = append(packages, candidate)
			}
		}
	}

	if err := json.NewEncoder(os.Stdout).Encode(packages); err != nil {
		return fmt.Errorf("failed to encode packages: %w", err)
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
