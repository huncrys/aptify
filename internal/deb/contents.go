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
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/dpeckett/archivefs/arfs"
	"github.com/dpeckett/archivefs/tarfs"
	"github.com/dpeckett/uncompr"
)

// GetPackageContents lists the files shipped by the package named by fsys and
// name, which is what a Contents indice describes it by.
func GetPackageContents(fsys fs.FS, name string) ([]string, error) {
	f, err := openPackage(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("failed to open package file: %w", err)
	}
	defer func() { _ = f.Close() }()

	debFS, err := arfs.Open(f)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}

	if err := ensureIsDebianPackage(debFS); err != nil {
		return nil, err
	}

	// Look for data archive in the debian package.
	entries, err := debFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read debian package: %w", err)
	}

	var dataArchiveFilename string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "data.tar") {
			dataArchiveFilename = entry.Name()
			break
		}
	}
	if dataArchiveFilename == "" {
		return nil, fmt.Errorf("failed to find data archive in debian package")
	}

	dataArchiveFile, err := debFS.Open(dataArchiveFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open data archive: %w", err)
	}

	dataArchiveReader, err := uncompr.NewReader(dataArchiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data archive: %w", err)
	}

	// Write data archive to temporary file (as we need a seekable reader for the
	// tarfs implementation).
	tempFile, err := spill(dataArchiveReader)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}()

	dataArchiveFS, err := tarfs.Open(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open data archive: %w", err)
	}

	var contents []string
	err = fs.WalkDir(dataArchiveFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk data archive: %w", err)
		}

		if d.IsDir() {
			return nil
		}

		contents = append(contents, path)

		return nil
	})

	return contents, err
}
