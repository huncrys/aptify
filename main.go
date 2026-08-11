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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/urfave/cli/v3"
	"oaklab.hu/debian/aptify/internal/constants"
	"oaklab.hu/debian/aptify/internal/keys"
	"oaklab.hu/debian/aptify/internal/repo"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/aptify/internal/util"
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
					slog.Info("Generating RSA key")

					entity, err := keys.Generate(cmd.String("name"), cmd.String("comment"), cmd.String("email"))
					if err != nil {
						return err
					}

					confDir := cmd.String("config-dir")

					slog.Info("Saving key pair", slog.String("dir", confDir))

					return keys.WritePrivate(filepath.Join(confDir, "aptify_private.asc"), entity)
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
						Usage:   "Directory to store the repository, or an s3://bucket/prefix URL",
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

					fsys, err := repofs.New(ctx, repoDir)
					if err != nil {
						return err
					}

					privateKeyPath := filepath.Join(cmd.String("config-dir"), "aptify_private.asc")

					return repo.Build(repo.Options{
						FS:             fsys,
						ConfigPath:     cmd.String("config"),
						PrivateKeyPath: privateKeyPath,
						Force:          cmd.Bool("force"),
						Reread:         cmd.Bool("reread"),
					})
				},
			},
			{
				Name:  "inspect",
				Usage: "Dump all packages in the repository as JSON",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "repository-dir",
						Aliases: []string{"d"},
						Usage:   "Directory containing the repository, or an s3://bucket/prefix URL",
						Value:   "repository",
					},
				},
				Before: util.BeforeAll(initLogger),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fsys, err := repofs.New(ctx, cmd.String("repository-dir"))
					if err != nil {
						return err
					}

					return repo.Inspect(fsys, os.Stdout)
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
