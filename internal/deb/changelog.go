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

package deb

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dpeckett/archivefs/arfs"
	"github.com/dpeckett/archivefs/tarfs"
	"github.com/dpeckett/uncompr"
)

var (
	ErrChangelogSymlink = errors.New("changelog folder is a symlink")

	// ErrPackageUnreadable reports that the package file itself could not be
	// opened, which is not the same as it shipping no changelog: the caller
	// publishes a placeholder for the latter and must not for this.
	ErrPackageUnreadable = errors.New("package file cannot be opened")
)

// GetPackageChangelog extracts the changelog of the package named by fsys and
// filename, which ships it under its own name or under that of the source
// package it was built from.
func GetPackageChangelog(fsys fs.FS, filename, source, name string) ([]byte, time.Time, error) {
	f, err := openPackage(fsys, filename)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: %w", ErrPackageUnreadable, err)
	}
	defer func() { _ = f.Close() }()

	debFS, err := arfs.Open(f)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to open archive: %w", err)
	}

	if err := ensureIsDebianPackage(debFS); err != nil {
		return nil, time.Time{}, err
	}

	// Look for data archive in the debian package.
	entries, err := debFS.ReadDir(".")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to read debian package: %w", err)
	}

	var dataArchiveFilename string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "data.tar") {
			dataArchiveFilename = entry.Name()
			break
		}
	}
	if dataArchiveFilename == "" {
		return nil, time.Time{}, fmt.Errorf("failed to find data archive in debian package")
	}

	dataArchiveFile, err := debFS.Open(dataArchiveFilename)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to open data archive: %w", err)
	}
	defer dataArchiveFile.Close()

	dataArchiveReader, err := uncompr.NewReader(dataArchiveFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to decompress data archive: %w", err)
	}
	defer dataArchiveReader.Close()

	// Write data archive to temporary file (as we need a seekable reader for the
	// tarfs implementation).
	tempFile, err := spill(dataArchiveReader)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}()

	dataArchiveFS, err := tarfs.Open(tempFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to open data archive: %w", err)
	}

	candidates := []string{
		filepath.Join("usr", "share", "doc", name, "changelog.Debian.gz"),
		filepath.Join("usr", "share", "doc", name, "changelog.gz"),
	}

	if source != name && source != "" {
		candidates = append(candidates, filepath.Join("usr", "share", "doc", source, "changelog.Debian.gz"))
		candidates = append(candidates, filepath.Join("usr", "share", "doc", source, "changelog.gz"))
	}

	for _, candidate := range candidates {
		changelogFile, err := dataArchiveFS.Open(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				for _, linkcandidate := range []string{filepath.Dir(candidate), candidate} {
					if stat, err := dataArchiveFS.StatLink(linkcandidate); err == nil {
						if stat.Mode()&os.ModeSymlink != 0 {
							return nil, f.modTime, ErrChangelogSymlink
						}
					}
				}
				continue
			}
			return nil, time.Time{}, fmt.Errorf("failed to open changelog file: %w", err)
		}
		stat, err := changelogFile.Stat()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to stat changelog file: %w", err)
		}
		defer changelogFile.Close()
		changelogReader, err := uncompr.NewReader(changelogFile)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to decompress changelog file: %w", err)
		}
		defer changelogReader.Close()
		changelogData, err := io.ReadAll(changelogReader)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to read changelog file: %w", err)
		}
		if len(changelogData) > 0 {
			return changelogData, stat.ModTime(), nil
		}
	}

	// The package's own modification time dates the placeholder the caller
	// writes, so that the published file does not carry the time of the build.
	return nil, f.modTime, os.ErrNotExist
}
