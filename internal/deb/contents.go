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
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/mholt/archives"
	_ "oaklab.hu/debian/aptify/internal/archivesext"
)

func GetPackageContents(path string) ([]string, error) {
	debFS, err := archives.FileSystem(context.TODO(), path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}

	if err := ensureIsDebianPackage(debFS); err != nil {
		return nil, err
	}

	// Look for data archive in the debian package.
	entries, err := fs.ReadDir(debFS, ".")
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

	// Write data archive to temporary file (as we need a seekable reader for the
	// tarfs implementation).
	tempFile, err := os.CreateTemp("", dataArchiveFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tempFile.Close()
	defer os.Remove(tempFile.Name())

	if _, err := io.Copy(tempFile, dataArchiveFile); err != nil {
		return nil, fmt.Errorf("failed to write data archive to temporary file: %w", err)
	}

	// Seek to beginning of temporary file.
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to beginning of temporary file: %w", err)
	}

	dataArchiveFS, err := archives.FileSystem(context.TODO(), dataArchiveFilename, tempFile)
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
