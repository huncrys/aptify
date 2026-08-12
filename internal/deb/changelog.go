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
	"io/fs"
	"time"
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
	scan, err := ScanPackage(fsys, filename)
	if err != nil {
		return nil, time.Time{}, err
	}

	return scan.Changelog(source, name)
}
