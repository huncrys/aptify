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

package deb

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
)

// packageFile is an open .deb, ready for the random access an ar archive
// needs.
type packageFile struct {
	io.ReaderAt

	// modTime is the modification time of the package itself, which is what
	// dates a changelog the caller has to synthesise.
	modTime time.Time

	close func() error
}

// Close releases the file, and the scratch copy of it if there was one.
func (p *packageFile) Close() error {
	return p.close()
}

// openPackage opens a package for reading. An ar archive is read out of order,
// so it needs an io.ReaderAt: a local file already is one, and anything else -
// a package sitting on remote storage - is spilled to a scratch file first,
// which is the price of reading it at all.
func openPackage(fsys fs.FS, name string) (*packageFile, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}

	// A package that cannot be statted still dates whatever is synthesised
	// from it, just by the read rather than by the archive.
	modTime := time.Now()
	if stat, err := f.Stat(); err == nil {
		modTime = stat.ModTime()
	}

	if readerAt, ok := f.(io.ReaderAt); ok {
		return &packageFile{ReaderAt: readerAt, modTime: modTime, close: f.Close}, nil
	}

	spilled, err := spill(f)
	_ = f.Close()

	if err != nil {
		return nil, err
	}

	return &packageFile{
		ReaderAt: spilled,
		modTime:  modTime,
		close: func() error {
			err := spilled.Close()
			if removeErr := os.Remove(spilled.Name()); err == nil {
				err = removeErr
			}

			return err
		},
	}, nil
}

// spill copies a reader into a scratch file, which is what turns a stream into
// something an archive can be read out of.
func spill(r io.Reader) (*os.File, error) {
	f, err := os.CreateTemp("", "package.deb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())

		return nil, fmt.Errorf("failed to write package to temporary file: %w", err)
	}

	return f, nil
}
