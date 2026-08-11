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
	"io/fs"
	"log/slog"
	"path"
	"strings"
	stdtime "time"

	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/filehash"
	"oaklab.hu/debian/deb822/types/list"
)

// byHashDir is the directory an index's by-hash entries for one algorithm are
// published in, relative to the release directory and slash separated.
func byHashDir(indicePath, algorithm string) string {
	return path.Join(path.Dir(indicePath), hashsum.ByHashDirName, algorithm)
}

// relativeName is name relative to base. Both are slash separated names of the
// same filesystem, and base is one of name's parents, which is what a walk
// rooted at base hands back.
func relativeName(base, name string) string {
	if base == "." {
		return name
	}

	return strings.TrimPrefix(strings.TrimPrefix(name, base), "/")
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

// byHashComplete reports whether every entry of the sets is published.
func byHashComplete(fsys repofs.FS, releaseDir string, sets map[string]map[string]bool) bool {
	for dir, hashes := range sets {
		for hash := range hashes {
			if _, err := fsys.Stat(path.Join(releaseDir, dir, hash)); err != nil {
				slog.Info("Republishing release, by-hash entry is missing",
					slog.String("entry", path.Join(dir, hash)))

				return false
			}
		}
	}

	return true
}

// linkByHash publishes every checksum of every index as a second name serving
// the index itself, so that a client which read a release can still fetch what
// it names after a later build has replaced the index. Locally that is a hard
// link: one inode holds the content however many names point at it.
func linkByHash(fsys repofs.FS, releaseDir string, sums []hashsum.Sums) error {
	for _, s := range sums {
		indicePath := path.Join(releaseDir, s.Path)

		for _, digest := range s.Digests() {
			dir := path.Join(releaseDir, byHashDir(s.Path, digest.Algorithm))
			if err := fsys.MkdirAll(dir); err != nil {
				return fmt.Errorf("failed to create by-hash directory: %w", err)
			}

			entryPath := path.Join(dir, digest.Hash)
			if _, err := fsys.Stat(entryPath); err == nil {
				// The name is the digest of the content, so an entry that is
				// already there holds exactly these bytes.
				continue
			} else if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("failed to stat by-hash entry: %w", err)
			}

			if err := fsys.Clone(indicePath, entryPath); err != nil {
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
func pruneByHash(fsys repofs.FS, releaseDir string, current, previous map[string]map[string]bool, retention stdtime.Duration) error {
	now := stdtime.Now()

	err := fs.WalkDir(fsys, releaseDir, func(dirPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() || d.Name() != hashsum.ByHashDirName {
			return nil
		}

		algorithms, err := fsys.ReadDir(dirPath)
		if err != nil {
			return err
		}

		for _, algorithm := range algorithms {
			if !algorithm.IsDir() {
				continue
			}

			algorithmDir := path.Join(dirPath, algorithm.Name())

			// The by-hash sets are keyed relative to the release directory,
			// which is what a Release file names its indices by.
			key := relativeName(releaseDir, algorithmDir)

			entries, err := fsys.ReadDir(algorithmDir)
			if err != nil {
				return err
			}

			for _, entry := range entries {
				if entry.IsDir() || current[key][entry.Name()] {
					continue
				}

				entryPath := path.Join(algorithmDir, entry.Name())

				if previous[key][entry.Name()] {
					// Superseded by this build: start its retention window now.
					if err := fsys.Chtimes(entryPath, now); err != nil {
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

				if err := fsys.Remove(entryPath); err != nil {
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
func removeByHash(fsys repofs.FS, releaseDir string) error {
	err := fs.WalkDir(fsys, releaseDir, func(dirPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() || d.Name() != hashsum.ByHashDirName {
			return nil
		}

		slog.Info("Removing by-hash directory", slog.String("dir", dirPath))

		if err := fsys.RemoveAll(dirPath); err != nil {
			return fmt.Errorf("failed to remove by-hash directory: %w", err)
		}

		return fs.SkipDir
	})
	if err != nil {
		return fmt.Errorf("failed to remove by-hash directories: %w", err)
	}

	return nil
}
