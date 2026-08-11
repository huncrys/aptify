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

package repofs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// osFS is a repository published to a local directory. Names are converted
// from slashes at this boundary and nowhere else.
type osFS struct {
	// fs.FS is the read half, os.DirFS rooted at the directory, which is also
	// what rejects a name that would escape it.
	fs.FS

	root string
}

var _ FS = (*osFS)(nil)

// NewOS is the repository stored in a local directory. The directory does not
// have to exist yet.
func NewOS(root string) FS {
	return &osFS{FS: os.DirFS(root), root: root}
}

// LocalFile addresses a file outside any repository - a source .deb, which is
// local whatever the repository is published to - as an io/fs name, so that it
// can be handed to the same readers.
func LocalFile(path string) (fs.FS, string) {
	return os.DirFS(filepath.Dir(path)), filepath.Base(path)
}

func (o *osFS) Name() string {
	return o.root
}

func (o *osFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(o.FS, name)
}

func (o *osFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(o.FS, name)
}

func (o *osFS) Glob(pattern string) ([]string, error) {
	// Matched against the read half rather than against o itself, which would
	// recurse: fs.Glob prefers a GlobFS when it is handed one.
	return fs.Glob(o.FS, pattern)
}

// WriteFile writes body through a temporary in the same directory and renames
// it into place. The published file may be hard linked from the by-hash tree,
// where rewriting it in place would silently change the contents served under
// its old checksum; the temporary is dot prefixed so that a crashed build
// cannot leave behind something the Release globs would match and sign.
func (o *osFS) WriteFile(name string, body []byte, perm fs.FileMode, mtime time.Time) error {
	return o.publish(name, perm, mtime, func(f *os.File) error {
		_, err := f.Write(body)

		return err
	})
}

// WriteFrom streams r into place, the same way WriteFile publishes a body it
// already holds. The size is not needed on a local disk.
func (o *osFS) WriteFrom(name string, r io.Reader, _ int64, mtime time.Time) error {
	return o.publish(name, 0o644, mtime, func(f *os.File) error {
		_, err := io.Copy(f, r)

		return err
	})
}

// publish creates the temporary, hands it to write, and renames it over name.
// Nothing is left behind when write fails.
func (o *osFS) publish(name string, perm fs.FileMode, mtime time.Time, write func(*os.File) error) error {
	path, err := o.path(name)
	if err != nil {
		return err
	}

	dir, base := filepath.Dir(path), filepath.Base(path)

	f, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpPath := f.Name()

	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := write(f); err != nil {
		_ = f.Close()

		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Dated before it is published, so the file is never briefly live under
	// the time of the build.
	if !mtime.IsZero() {
		if err := os.Chtimes(tmpPath, time.Time{}, mtime); err != nil {
			return fmt.Errorf("failed to set file modification time: %w", err)
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}
	tmpPath = ""

	return nil
}

func (o *osFS) MkdirAll(name string) error {
	path, err := o.path(name)
	if err != nil {
		return err
	}

	return os.MkdirAll(path, 0o755)
}

func (o *osFS) Remove(name string) error {
	path, err := o.path(name)
	if err != nil {
		return err
	}

	return os.Remove(path)
}

func (o *osFS) RemoveAll(name string) error {
	path, err := o.path(name)
	if err != nil {
		return err
	}

	return os.RemoveAll(path)
}

// Clone hard links newname to oldname: one inode holds the content however
// many names point at it, which is what makes a by-hash tree cost nothing.
func (o *osFS) Clone(oldname, newname string) error {
	from, err := o.path(oldname)
	if err != nil {
		return err
	}

	to, err := o.path(newname)
	if err != nil {
		return err
	}

	return os.Link(from, to)
}

func (o *osFS) Chtimes(name string, mtime time.Time) error {
	path, err := o.path(name)
	if err != nil {
		return err
	}

	return os.Chtimes(path, time.Time{}, mtime)
}

// path is the local path of a repository relative name.
func (o *osFS) path(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "path", Path: name, Err: fs.ErrInvalid}
	}

	return filepath.Join(o.root, filepath.FromSlash(name)), nil
}
