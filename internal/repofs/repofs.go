// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Copyright (C) 2026 Kristof Bach <crys@crys.hu>.
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

// Package repofs is the storage a repository is published to. The pipeline
// addresses everything it reads and writes by a repository relative,
// slash separated name, so that the same build can run against a local
// directory or against something remote.
//
// The read half is plain io/fs. The write half is deliberately small and
// shaped by what the pipeline needs rather than by POSIX: publishing a file,
// streaming a large one in, making a second name serve a file's bytes cheaply,
// and recording a modification time.
package repofs

import (
	"io"
	"io/fs"
	"time"
)

// FS is a repository's storage.
//
// Every name is a slash separated path relative to the repository root, as
// io/fs requires: build it with path.Join, never filepath.Join.
type FS interface {
	fs.FS
	fs.StatFS
	fs.ReadDirFS
	fs.GlobFS

	// Name is where the repository lives, for logs and error messages. It is
	// not a path anything is resolved against.
	Name() string

	// WriteFile publishes body under name, atomically: a reader either sees
	// what was there before or the whole of the new content. A zero mtime
	// records none, leaving the file dated by the write itself.
	WriteFile(name string, body []byte, perm fs.FileMode, mtime time.Time) error

	// WriteFrom publishes size bytes read from r under name, for content too
	// large to hold in memory. The size is what the implementation is told to
	// expect, not a limit it enforces.
	WriteFrom(name string, r io.Reader, size int64, mtime time.Time) error

	// MkdirAll makes sure name can hold files. Storage without directories
	// implements it as a no-op.
	MkdirAll(name string) error

	Remove(name string) error
	RemoveAll(name string) error

	// Clone makes newname serve oldname's bytes as cheaply as the storage
	// allows, without reading them through this process. It is what publishes
	// the by-hash tree.
	Clone(oldname, newname string) error

	// Chtimes records name's modification time. This is the by-hash retention
	// clock: an entry is touched as it leaves the release and deleted a
	// retention window later.
	Chtimes(name string, mtime time.Time) error
}
