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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/adrg/xdg"
	"github.com/dpeckett/aptify/internal/config"
	"github.com/dpeckett/aptify/internal/config/v1alpha1"
	"github.com/dpeckett/aptify/internal/constants"
	"github.com/dpeckett/aptify/internal/deb"
	"github.com/dpeckett/aptify/internal/sha256sum"
	"github.com/dpeckett/aptify/internal/util"
	"github.com/dpeckett/deb822"
	"github.com/dpeckett/deb822/types"
	"github.com/dpeckett/deb822/types/arch"
	"github.com/dpeckett/deb822/types/list"
	"github.com/dpeckett/deb822/types/time"
	"github.com/dpeckett/uncompr"
	cp "github.com/otiai10/copy"
	"github.com/urfave/cli/v2"
)

func main() {
	defaultConfDir, _ := xdg.ConfigFile("aptify")

	persistentFlags := []cli.Flag{
		&cli.GenericFlag{
			Name:    "log-level",
			EnvVars: []string{"LOG_LEVEL"},
			Usage:   "Set the log verbosity level",
			Value:   util.FromSlogLevel(slog.LevelInfo),
		},
		&cli.StringFlag{
			Name:    "config-dir",
			EnvVars: []string{"CONFIG_DIR"},
			Usage:   "Directory to store configuration",
			Value:   defaultConfDir,
		},
	}

	initLogger := func(c *cli.Context) error {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: (*slog.Level)(c.Generic("log-level").(*util.LevelFlag)),
		})))

		return nil
	}

	initConfDir := func(c *cli.Context) error {
		confDir := c.String("config-dir")
		if confDir == "" {
			return fmt.Errorf("no configuration directory specified")
		}

		if err := os.MkdirAll(confDir, 0o700); err != nil {
			return fmt.Errorf("failed to create configuration directory: %w", err)
		}

		return nil
	}

	app := &cli.App{
		Name:    "aptify",
		Usage:   "Create apt repositories from Debian packages",
		Version: constants.Version,
		Commands: []*cli.Command{
			{
				Name:  "init-keys",
				Usage: "Generate a new GPG key pair for signing releases",
				Flags: append([]cli.Flag{
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
				}, persistentFlags...),
				Before: util.BeforeAll(initLogger, initConfDir),
				Action: func(c *cli.Context) error {
					entityConfig := &packet.Config{
						RSABits: 4096,
						Time:    stdtime.Now,
					}

					slog.Info("Generating RSA key")

					// Create a new entity.
					entity, err := openpgp.NewEntity(c.String("name"), c.String("comment"), c.String("email"), entityConfig)
					if err != nil {
						return fmt.Errorf("failed to create entity: %w", err)
					}

					slog.Info("Saving key pair", slog.String("dir", c.String("config-dir")))

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

					confDir := c.String("config-dir")

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
				Flags: append([]cli.Flag{
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
				}, persistentFlags...),
				Before: util.BeforeAll(initLogger, initConfDir),
				Action: func(c *cli.Context) error {
					repoDir := c.String("repository-dir")

					slog.Info("Building repository", slog.String("dir", repoDir))

					privateKeyPath := filepath.Join(c.String("config-dir"), "aptify_private.asc")

					return buildRepository(
						repoDir,
						c.String("config"),
						privateKeyPath,
					)
				},
			},
			{
				Name:  "inspect",
				Usage: "Dump all packages in the repository as JSON",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:    "repository-dir",
						Aliases: []string{"d"},
						Usage:   "Directory containing the repository",
						Value:   "repository",
					},
				}, persistentFlags...),
				Before: util.BeforeAll(initLogger),
				Action: func(c *cli.Context) error {
					repoDir := c.String("repository-dir")

					return inspectRepository(repoDir)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Error", slog.Any("error", err))
		os.Exit(1)
	}
}

func buildRepository(repoDir, confPath, privateKeyPath string) error {
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
	poolReferences := make(map[string]int)

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

				reader, err := os.Open(packagesFile)
				if err != nil {
					return fmt.Errorf("failed to open Packages file: %w", err)
				}
				defer reader.Close()
				decoder, err := deb822.NewDecoder(reader, nil)
				if err != nil {
					return fmt.Errorf("failed to create decoder for Packages file: %w", err)
				}

				var packages []types.Package
				if err := decoder.Decode(&packages); err != nil {
					return fmt.Errorf("failed to decode Packages file: %w", err)
				}

				packagesForReleaseComponent[releaseComponent] = append(packagesForReleaseComponent[releaseComponent], packages...)

				// Get the architectures from the Packages file.
				for _, pkg := range packages {
					poolReferences[pkg.Filename]++
					archsForReleaseComponent[releaseComponent][pkg.Architecture.String()] = true
				}
			}
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

					pkg.SHA256, err = sha256sum.File(pkgPath)
					if err != nil {
						return fmt.Errorf("failed to hash package: %w", err)
					}

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
					poolReferences[pkg.Filename]++

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
			versions := make(map[string][]types.Package)
			for _, pkg := range packagesForReleaseComponent[releaseComponent] {
				// Use the package name and architecture as the key.
				key := fmt.Sprintf("%s/%s", pkg.Name, pkg.Architecture.String())
				// If the key already exists, append the package to the list.
				versions[key] = append(versions[key], pkg)
			}

			for _, pkgs := range versions {
				countMustRemove := max(len(pkgs)-int(componentConf.MaxVersions), 0)
				if countMustRemove == 0 {
					slog.Debug("No versions to remove for package",
						slog.String("package", pkgs[0].Name),
						slog.String("architecture", pkgs[0].Architecture.String()),
						slog.String("release_component", releaseComponent),
						slog.Int("max_versions", int(componentConf.MaxVersions)),
						slog.Int("current_versions", len(pkgs)),
					)
				}

				// Sort the packages by version.
				slices.SortStableFunc(pkgs, func(a, b types.Package) int {
					return a.Compare(b)
				})

				for _, pkgToRemove := range pkgs[:countMustRemove] {
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
					poolReferences[pkgToRemove.Filename]--
				}
			}
		}
	}

	// Create release files.
	for _, releaseConf := range conf.Releases {
		var architectures []arch.Arch

		modified := false

		for _, componentConf := range releaseConf.Components {
			releaseComponent := fmt.Sprintf("%s/%s", releaseConf.Name, componentConf.Name)

			for architecture := range archsForReleaseComponent[releaseComponent] {
				componentDir := filepath.Join(repoDir, "dists", releaseConf.Name, componentConf.Name)
				archDir := filepath.Join(componentDir, "binary-"+architecture)

				if err := os.MkdirAll(archDir, 0o755); err != nil {
					return fmt.Errorf("failed to create dists subdirectory: %w", err)
				}

				packages := packagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredPackages := make([]types.Package, 0, len(packages))
				for _, pkg := range packages {
					if pkg.Architecture.String() == architecture {
						filteredPackages = append(filteredPackages, pkg)
					}
				}
				packages = filteredPackages

				newPackages := newPackagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredNewPackages := make([]types.Package, 0, len(newPackages))
				for _, pkg := range newPackages {
					if pkg.Architecture.String() == architecture {
						filteredNewPackages = append(filteredNewPackages, pkg)
					}
				}
				newPackages = filteredNewPackages

				removedPackages := removedPackagesForReleaseComponent[releaseComponent]
				// Filter out packages that don't match the architecture.
				filteredRemovedPackages := make([]types.Package, 0, len(removedPackages))
				for _, pkg := range removedPackages {
					if pkg.Architecture.String() == architecture {
						filteredRemovedPackages = append(filteredRemovedPackages, pkg)
					}
				}
				removedPackages = filteredRemovedPackages

				if len(newPackages) == 0 && len(removedPackages) == 0 {
					slog.Info("Skipping index generation, no new or removed packages found",
						slog.String("dir", archDir),
					)

					continue
				}

				modified = true

				sort.Slice(packages, func(i, j int) bool {
					return packages[i].Compare(packages[j]) < 0
				})
				sort.Slice(newPackages, func(i, j int) bool {
					return newPackages[i].Compare(newPackages[j]) < 0
				})
				sort.Slice(removedPackages, func(i, j int) bool {
					return removedPackages[i].Compare(removedPackages[j]) < 0
				})

				if err := writePackagesIndice(archDir, packages); err != nil {
					return fmt.Errorf("failed to write package lists: %w", err)
				}

				// TODO: Re-write contents file for removed packages.
				if err := writeContentsIndice(repoDir, componentDir, newPackages, architecture); err != nil {
					return fmt.Errorf("failed to write contents file: %w", err)
				}

				architectures = append(architectures, arch.MustParse(architecture))
			}
		}

		releaseDir := filepath.Join(repoDir, "dists", releaseConf.Name)
		if !modified {
			slog.Info("Skipping release generation, no changes", slog.String("dir", releaseDir))
			continue
		}

		if err := os.MkdirAll(releaseDir, 0o755); err != nil {
			return fmt.Errorf("failed to create release directory: %w", err)
		}

		if err := writeReleaseFile(releaseDir, releaseConf, architectures, privateKey); err != nil {
			return fmt.Errorf("failed to write release: %w", err)
		}
	}

	for poolPath, references := range poolReferences {
		if references > 0 {
			continue
		}

		slog.Info("Removing unused file from pool",
			slog.String("file", poolPath))
		if err := os.Remove(filepath.Join(repoDir, poolPath)); err != nil {
			return fmt.Errorf("failed to remove unused package file: %w", err)
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
		os.Chtimes(signingKeyFilePath, stdtime.Time{}, stat.ModTime())
	}

	return nil
}

func writePackagesIndice(archDir string, packages []types.Package) error {
	slog.Info("Writing Packages indice",
		slog.String("dir", archDir), slog.Int("count", len(packages)))

	var packageList bytes.Buffer
	if err := deb822.Marshal(&packageList, packages); err != nil {
		return fmt.Errorf("failed to marshal packages: %w", err)
	}

	for _, name := range []string{"Packages", "Packages.gz", "Packages.xz"} {
		f, err := os.Create(filepath.Join(archDir, name))
		if err != nil {
			return fmt.Errorf("failed to create Packages file: %w", err)
		}
		defer f.Close()

		w, err := uncompr.NewWriter(f, f.Name())
		if err != nil {
			return fmt.Errorf("failed to create compression writer: %w", err)
		}
		defer w.Close()

		if _, err := w.Write(packageList.Bytes()); err != nil {
			return fmt.Errorf("failed to write Packages file: %w", err)
		}
	}

	return nil
}

func writeContentsIndice(repoDir, componentDir string, newPackages []types.Package, arch string) error {
	f, err := os.OpenFile(filepath.Join(componentDir, fmt.Sprintf("Contents-%s.gz", arch)), os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("failed to open Contents file: %w", err)
	}
	defer f.Close()

	packageFiles := make(map[string][]string)

	if r, err := uncompr.NewReader(f); err == nil {
		defer r.Close()

		// Read r into contents with fmt.Fscanf
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid Contents line: %s", line)
			}
			path := parts[0]
			packageNames := strings.Split(parts[1], ",")
			for _, pkg := range packageNames {
				if !slices.Contains(packageFiles[pkg], path) {
					packageFiles[pkg] = append(packageFiles[pkg], path)
				}
			}
		}
	} else if err != io.EOF {
		return fmt.Errorf("failed to create decompression reader: %w", err)
	}

	w, err := uncompr.NewWriter(f, f.Name())
	if err != nil {
		return fmt.Errorf("failed to create compression writer: %w", err)
	}
	defer w.Close()

	slog.Info("Collecting package contents", slog.String("dir", componentDir))

	for _, pkg := range newPackages {
		pkgContents, err := deb.GetPackageContents(filepath.Join(repoDir, pkg.Filename))
		if err != nil {
			return fmt.Errorf("failed to get package contents: %w", err)
		}

		for k := range packageFiles {
			parts := strings.SplitN(k, "/", 2)
			slices.Reverse(parts)
			name := parts[0]

			if name == pkg.Name {
				delete(packageFiles, k)
			}
		}

		qualifiedPackageName := pkg.Name
		if pkg.Section != "" {
			qualifiedPackageName = fmt.Sprintf("%s/%s", pkg.Section, pkg.Name)
		}

		packageFiles[qualifiedPackageName] = pkgContents
	}

	contents := make(map[string][]string)
	for pkg, paths := range packageFiles {
		for _, path := range paths {
			if !slices.Contains(contents[path], pkg) {
				contents[path] = append(contents[path], pkg)
			}
		}
	}

	paths := make([]string, 0, len(contents))
	for k := range contents {
		paths = append(paths, k)
	}

	sort.Strings(paths)

	slog.Info("Writing Contents indice",
		slog.String("dir", componentDir), slog.Int("count", len(paths)))

	f.Truncate(0)
	f.Seek(0, io.SeekStart)
	for _, path := range paths {
		if _, err := fmt.Fprintf(w, "%s %s\n", path, strings.Join(contents[path], ",")); err != nil {
			return fmt.Errorf("failed to write contents: %w", err)
		}
	}

	return nil
}

func writeReleaseFile(releaseDir string, releaseConf v1alpha1.ReleaseConfig, architectures []arch.Arch, privateKey *openpgp.Entity) error {
	slog.Info("Writing Release file", slog.String("dir", releaseDir))

	var components []string
	for _, component := range releaseConf.Components {
		components = append(components, component.Name)
	}

	r := types.Release{
		Origin:        releaseConf.Origin,
		Label:         releaseConf.Label,
		Suite:         releaseConf.Suite,
		Version:       releaseConf.Version,
		Codename:      releaseConf.Name,
		Changelogs:    "no",
		Date:          time.Time(stdtime.Now().UTC()),
		Architectures: list.SpaceDelimited[arch.Arch](architectures),
		Components:    list.SpaceDelimited[string](components),
		Description:   releaseConf.Description,
	}

	var err error
	r.SHA256, err = sha256sum.Directory(releaseDir, []string{"*/binary-*/Packages*", "*/Contents-*"})
	if err != nil {
		return fmt.Errorf("failed to hash release: %w", err)
	}

	releaseFile, err := os.Create(filepath.Join(releaseDir, "InRelease"))
	if err != nil {
		return fmt.Errorf("failed to create Release file: %w", err)
	}
	defer releaseFile.Close()

	encoder, err := deb822.NewEncoder(releaseFile, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create encoder: %w", err)
	}
	defer encoder.Close()

	if err := encoder.Encode(r); err != nil {
		return fmt.Errorf("failed to encode release: %w", err)
	}

	return nil
}

func poolPathForPackage(componentName string, pkg *types.Package) string {
	source := strings.TrimSpace(pkg.Source)
	if pkg.Source == "" {
		source = strings.TrimSpace(pkg.Name)
	}

	// If the source has a version, lop it off.
	if strings.Contains(source, "(") {
		source = source[:strings.Index(source, "(")]
	}

	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		prefix = source[:4]
	}

	return filepath.Join("pool", componentName, prefix, source,
		fmt.Sprintf("%s_%s_%s.deb", pkg.Name, pkg.Version, pkg.Architecture))
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
		reader, err := os.Open(file)
		if err != nil {
			return fmt.Errorf("failed to open Packages file: %w", err)
		}
		defer reader.Close()
		decoder, err := deb822.NewDecoder(reader, nil)
		if err != nil {
			return fmt.Errorf("failed to create decoder for Packages file: %w", err)
		}

		var candidates []types.Package
		if err := decoder.Decode(&candidates); err != nil {
			return fmt.Errorf("failed to decode Packages file: %w", err)
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

	json.NewEncoder(os.Stdout).Encode(packages)

	return nil
}
