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
	"io/fs"
	"log/slog"
	"os"
	"slices"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"oaklab.hu/debian/aptify/internal/config"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/keys"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/types"
)

// Options is everything a repository build is given: where the repository is
// published, the configuration describing it, the key it is signed with, and
// the two switches that override the incremental skips.
type Options struct {
	FS             repofs.FS
	ConfigPath     string
	PrivateKeyPath string
	Force          bool
	Reread         bool
}

// build is the state one repository build carries across its stages. The
// repository itself is the only state store there is, so the maps below are
// what the stages hand each other: what the repository already published, what
// this build added and removed, and which pool files are in play.
type build struct {
	fsys           repofs.FS
	privateKeyPath string
	conf           *v1alpha1.Repository
	privateKey     *openpgp.Entity
	force, reread  bool

	// The published packages, and this build's additions and removals, keyed by
	// "<release>/<component>".
	packages map[string][]types.Package
	added    map[string][]types.Package
	removed  map[string][]types.Package
	// The architectures each release/component publishes.
	archs map[string]map[string]bool
	// The pool path each ingested .deb was copied to, so a file shared by
	// several components is only copied once.
	poolPaths map[string]string
	// The local file each ingested pool path was copied from, so a package
	// this build just published is read from there rather than fetched back
	// out of the pool.
	sourcePaths map[string]string
	// Every pool path seen while loading and ingesting, which is what the pool
	// garbage collection considers.
	candidates map[string]bool
	// The release/components whose Packages indices the backfill made stale.
	backfilled map[string]bool
	// The walk of each package's payload, keyed by pool path, so the Contents
	// stage and the changelogs share one pass over a .deb. Nothing rewrites a
	// pool file between stages; invalidate this if that ever changes.
	scans map[string]*deb.Scan
}

// Build publishes the repository the configuration describes.
func Build(opts Options) error {
	b, err := newBuild(opts)
	if err != nil {
		return err
	}

	return b.run(b.ingest)
}

// newBuild reads everything a run needs before it touches the repository: the
// signing key and the configuration. Nothing here is specific to what the run
// will do to the package lists, which is why the one-off add and remove start
// the same way.
func newBuild(opts Options) (*build, error) {
	if _, err := os.Stat(opts.PrivateKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("private key not found; run 'aptify init-keys' to generate one")
	}

	privateKey, err := keys.Load(opts.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	confFile, err := os.Open(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = confFile.Close() }()

	conf, err := config.FromYAML(confFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return &build{
		fsys:           opts.FS,
		privateKeyPath: opts.PrivateKeyPath,
		conf:           conf,
		privateKey:     privateKey,
		force:          opts.Force,
		reread:         opts.Reread,

		packages:    make(map[string][]types.Package),
		added:       make(map[string][]types.Package),
		removed:     make(map[string][]types.Package),
		archs:       make(map[string]map[string]bool),
		poolPaths:   make(map[string]string),
		sourcePaths: make(map[string]string),
		candidates:  make(map[string]bool),
		scans:       make(map[string]*deb.Scan),
	}, nil
}

// run drives the stage sequence, with mutate standing in for whatever changes
// the package lists: the configured glob ingest for a build, a one-off add or
// remove otherwise. Everything downstream reads only b.packages, b.added and
// b.removed, so every entry point gets the same pruning, backfill, indices,
// pool collection, changelogs and signature.
func (b *build) run(mutate func() error) error {
	// Load existing state.
	if err := b.loadExisting(); err != nil {
		return err
	}

	// Ingest, or whatever else this run publishes.
	if err := mutate(); err != nil {
		return err
	}

	// Prune, then backfill.
	if err := b.prune(); err != nil {
		return err
	}

	if err := b.backfill(); err != nil {
		return err
	}

	// Write indices.
	if err := b.writeIndices(); err != nil {
		return err
	}

	// Garbage-collect the pool.
	if err := b.collectPoolGarbage(); err != nil {
		return err
	}

	// Changelogs.
	if err := b.changelogs(); err != nil {
		return err
	}

	// Signing key.
	return b.writeSigningKey()
}

// signingKeyName is where the public half of the signing key is published.
const signingKeyName = "signing_key.asc"

// writeSigningKey saves a copy of the public half of the signing key, keeping
// the private key's modification time so that a rebuild does not churn a
// mirrored repository.
func (b *build) writeSigningKey() error {
	if _, err := b.fsys.Stat(signingKeyName); err == nil {

		if signingKeyFile, err := b.fsys.Open(signingKeyName); err == nil {
			defer func() { _ = signingKeyFile.Close() }()

			if keyRing, err := openpgp.ReadArmoredKeyRing(signingKeyFile); err == nil {
				for _, publicKey := range keyRing {
					if slices.Equal(publicKey.PrimaryKey.Fingerprint, b.privateKey.PrimaryKey.Fingerprint) {
						slog.Info("Skipping writing signing key, no changes",
							slog.String("file", signingKeyName))
						return nil
					}
				}
			}
		}

		slog.Info("Signing key file does not match private key, overwriting",
			slog.String("file", signingKeyName))
	}

	slog.Info("Writing signing key file", slog.String("file", signingKeyName))

	var body bytes.Buffer
	if err := keys.WritePublic(&body, b.privateKey); err != nil {
		return err
	}

	// A private key that cannot be statted leaves the published copy dated by
	// the write itself.
	var mtime stdtime.Time
	if stat, err := os.Stat(b.privateKeyPath); err == nil {
		mtime = stat.ModTime()
	}

	if err := b.fsys.WriteFile(signingKeyName, body.Bytes(), 0o644, mtime); err != nil {
		return fmt.Errorf("failed to write signing key file: %w", err)
	}

	return nil
}

// poolFile addresses a published package for reading. A .deb this build
// ingested is read from the local file it was copied from: the pool copy is
// byte for byte the same, and fetching it back would be a download on remote
// storage.
func (b *build) poolFile(poolPath string) (fs.FS, string) {
	if sourcePath, ok := b.sourcePaths[poolPath]; ok {
		return repofs.LocalFile(sourcePath)
	}

	return b.fsys, poolPath
}

// scanPool walks a published package's payload, once per build: the Contents
// indice of every architecture and the changelogs all ask for the same .deb.
// A failure is not remembered, so that a package that cannot be read is
// reported as often as it is asked for.
func (b *build) scanPool(poolPath string) (*deb.Scan, error) {
	if scan, ok := b.scans[poolPath]; ok {
		return scan, nil
	}

	scan, err := deb.ScanPackage(b.poolFile(poolPath))
	if err != nil {
		return nil, err
	}

	b.scans[poolPath] = scan

	return scan, nil
}
