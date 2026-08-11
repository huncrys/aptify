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

package deb_test

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// streamFS hands out files that can only be read forwards, which is what a
// package fetched off remote storage is. A local file is an io.ReaderAt and an
// ar archive is read out of order, so this is the path that has to spill to a
// scratch file to work at all.
type streamFS struct {
	fs.FS

	opened int
}

func (s *streamFS) Open(name string) (fs.File, error) {
	f, err := s.FS.Open(name)
	if err != nil {
		return nil, err
	}

	s.opened++

	return streamFile{f}, nil
}

// streamFile deliberately implements no more than fs.File, hiding the ReadAt
// of the file underneath it.
type streamFile struct {
	f fs.File
}

func (s streamFile) Stat() (fs.FileInfo, error) { return s.f.Stat() }
func (s streamFile) Read(b []byte) (int, error) { return s.f.Read(b) }
func (s streamFile) Close() error               { return s.f.Close() }

// TestReadersAcceptAStreamOnlyFilesystem pins that every reader works on a
// filesystem whose files are streams, and reports the same thing it does for a
// local file.
func TestReadersAcceptAStreamOnlyFilesystem(t *testing.T) {
	const name = "hello-world_1.0_amd64.deb"

	stream := &streamFS{FS: os.DirFS(fixtureDir)}

	pkg, err := deb.GetMetadata(stream, name)
	require.NoError(t, err)

	wantPkg, err := deb.GetMetadata(fixture(name))
	require.NoError(t, err)
	assert.Equal(t, wantPkg, pkg)

	contents, err := deb.GetPackageContents(stream, name)
	require.NoError(t, err)

	wantContents, err := deb.GetPackageContents(fixture(name))
	require.NoError(t, err)
	assert.Equal(t, wantContents, contents)

	changelog, modTime, err := deb.GetPackageChangelog(stream, name, "hello-world", "hello-world")
	require.NoError(t, err)
	assert.NotEmpty(t, changelog)
	assert.False(t, modTime.IsZero())

	assert.Equal(t, 3, stream.opened, "the package was opened once per read")
}

// TestStreamedPackageDatesItsPlaceholder covers the timestamp the caller
// writes a synthetic changelog with: it comes from the package, which is
// statted through the filesystem rather than off a local file.
func TestStreamedPackageDatesItsPlaceholder(t *testing.T) {
	const name = "hello-world-dbgsym_1.0_amd64.deb"

	info, err := os.Stat(fixturePath(name))
	require.NoError(t, err)

	_, modTime, err := deb.GetPackageChangelog(&streamFS{FS: os.DirFS(fixtureDir)}, name,
		"hello-world", "hello-world-dbgsym")
	require.ErrorIs(t, err, deb.ErrChangelogSymlink)

	assert.True(t, info.ModTime().Equal(modTime), "want %s, got %s", info.ModTime(), modTime)
}

// TestStreamedPackageLeavesNoScratchFiles checks that the scratch copies a
// stream is spilled into are cleaned up.
func TestStreamedPackageLeavesNoScratchFiles(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	_, err := deb.GetPackageContents(&streamFS{FS: os.DirFS(fixtureDir)}, "hello-world_1.0_amd64.deb")
	require.NoError(t, err)

	left, err := os.ReadDir(os.TempDir())
	require.NoError(t, err)
	assert.Empty(t, left, "the scratch copies were not cleaned up")
}
