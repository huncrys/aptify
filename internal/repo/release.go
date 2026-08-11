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
	"crypto"
	"fmt"
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
	"oaklab.hu/debian/deb822/types/boolean"
	"oaklab.hu/debian/deb822/types/list"
	"oaklab.hu/debian/deb822/types/time"
)

// releaseIndiceGlobs selects the files a Release file publishes checksums for,
// relative to the release directory. Anything apt has to verify has to be
// matched here or it is signed for but unlisted. The patterns are deliberately
// narrow: `*/binary-*/*` would also match the by-hash entries, which are hard
// links to files already listed under their own names.
var releaseIndiceGlobs = []string{"*/binary-*/Packages*", "*/binary-*/Release", "*/Contents-*"}

func readReleaseFile(fsys repofs.FS, releaseDir string, privateKey *openpgp.Entity) (*types.Release, error) {
	releaseFile, err := fsys.Open(path.Join(releaseDir, "InRelease"))
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

// writeReleaseFile publishes the release stanza naming every indice of the
// release. published holds the checksums of the indices this build wrote or
// compared, keyed relative to the release directory; anything it does not
// cover is taken from the release being replaced, or hashed off the storage.
func (b *build) writeReleaseFile(releaseDir string, releaseConf v1alpha1.ReleaseConfig, architectures []arch.Arch, modified bool, publishedSums map[string]hashsum.Sums) error {
	fsys, conf, privateKey := b.fsys, b.conf, b.privateKey

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
	existing, err := readReleaseFile(fsys, releaseDir, privateKey)
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
		modified = !byHashComplete(fsys, releaseDir, previous)
	}

	if !modified {
		slog.Info("Skipping release generation, no changes", slog.String("dir", releaseDir))

		if byHash {
			// Nothing was superseded, but entries retired by an earlier build
			// still age out.
			return pruneByHash(fsys, releaseDir, previous, previous, conf.ByHashRetention())
		}

		return nil
	}

	slog.Info("Writing Release file", slog.String("dir", releaseDir))

	sums, err := releaseSums(fsys, releaseDir, publishedSums, existing, b.force)
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
		if err := linkByHash(fsys, releaseDir, sums); err != nil {
			return fmt.Errorf("failed to publish by-hash indices: %w", err)
		}
	}

	// One rendering of the stanza for all three files, so they cannot disagree.
	var body bytes.Buffer
	if err := deb822.Marshal(&body, r); err != nil {
		return fmt.Errorf("failed to encode release: %w", err)
	}

	if err := fsys.WriteFile(path.Join(releaseDir, "Release"), body.Bytes(), 0o644, stdtime.Time{}); err != nil {
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

	if err := fsys.WriteFile(path.Join(releaseDir, "Release.gpg"), detachedSignature.Bytes(), 0o644, stdtime.Time{}); err != nil {
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
	if err := fsys.WriteFile(path.Join(releaseDir, "InRelease"), inRelease.Bytes(), 0o644, stdtime.Time{}); err != nil {
		return fmt.Errorf("failed to write InRelease file: %w", err)
	}

	if !byHash {
		// The flag is gone from the release just published, so the tree it
		// described can go too. Never the other way round.
		return removeByHash(fsys, releaseDir)
	}

	return pruneByHash(fsys, releaseDir, current, previous, conf.ByHashRetention())
}

// releaseSums are the checksums a Release file publishes, one entry per indice
// the release names.
//
// The file list is globbed off the storage, so it describes what is actually
// published; only the checksums are taken from elsewhere. Each one comes from
// the cheapest source that describes the very bytes on the storage: what this
// build wrote or compared, else what the release being replaced recorded for a
// file this build did not touch, else a read. --force takes the last route for
// everything, which is the way out if the published bytes are suspect.
func releaseSums(fsys repofs.FS, releaseDir string, published map[string]hashsum.Sums, existing *types.Release, force bool) ([]hashsum.Sums, error) {
	names, err := releaseIndiceNames(fsys, releaseDir)
	if err != nil {
		return nil, err
	}

	recorded := recordedSums(existing)

	sums := make([]hashsum.Sums, 0, len(names))
	for _, name := range names {
		if !force {
			if s, ok := published[name]; ok {
				sums = append(sums, s)

				continue
			}

			if s, ok := recorded[name]; ok {
				sums = append(sums, s)

				continue
			}
		}

		s, err := hashsum.File(fsys, path.Join(releaseDir, name))
		if err != nil {
			return nil, err
		}
		s.Path = name

		sums = append(sums, s)
	}

	return sums, nil
}

// releaseIndiceNames lists the indices of a release, relative to its directory
// and in the order the Release file lists them.
func releaseIndiceNames(fsys repofs.FS, releaseDir string) ([]string, error) {
	var names []string

	seen := make(map[string]bool)
	for _, glob := range releaseIndiceGlobs {
		matches, err := fsys.Glob(path.Join(releaseDir, glob))
		if err != nil {
			return nil, fmt.Errorf("failed to find release indices: %w", err)
		}

		for _, match := range matches {
			name := relativeName(releaseDir, match)
			if seen[name] {
				continue
			}
			seen[name] = true

			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names, nil
}

// recordedSums are the checksums a release file records, keyed by file name. A
// file is only taken from it when all three algorithms describe it at the same
// size: a release published by an older aptify carries fewer, and a stanza
// that disagrees with itself is not a source of anything.
func recordedSums(release *types.Release) map[string]hashsum.Sums {
	if release == nil {
		return nil
	}

	sums := make(map[string]hashsum.Sums, len(release.SHA256))

	for _, hash := range release.SHA256 {
		sums[hash.Filename] = hashsum.Sums{Path: hash.Filename, Size: hash.Size, SHA256: hash.Hash}
	}

	for _, hash := range release.MD5Sum {
		if s, ok := sums[hash.Filename]; ok && s.Size == hash.Size {
			s.MD5 = hash.Hash
			sums[hash.Filename] = s
		}
	}

	for _, hash := range release.SHA1 {
		if s, ok := sums[hash.Filename]; ok && s.Size == hash.Size {
			s.SHA1 = hash.Hash
			sums[hash.Filename] = s
		}
	}

	maps.DeleteFunc(sums, func(_ string, s hashsum.Sums) bool {
		return s.MD5 == "" || s.SHA1 == "" || s.SHA256 == ""
	})

	return sums
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
