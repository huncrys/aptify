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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// Pins that the single walk answers exactly what the readers built on it do,
// for a package shipping a changelog and for one whose documentation directory
// is a symlink.
func TestScanPackageAnswersLikeTheReaders(t *testing.T) {
	tests := []struct {
		name string
		file string
		pkg  string
	}{
		{name: "binary package", file: "hello-world_1.0_amd64.deb", pkg: "hello-world"},
		{name: "architecture all package", file: "hello-world_3.0_all.deb", pkg: "hello-world"},
		{name: "symlinked doc directory", file: "hello-world-dbgsym_1.0_amd64.deb", pkg: "hello-world-dbgsym"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys, name := fixture(tt.file)

			scan, err := deb.ScanPackage(fsys, name)
			require.NoError(t, err)

			wantContents, err := deb.GetPackageContents(fixture(tt.file))
			require.NoError(t, err)
			assert.Equal(t, wantContents, scan.Contents)

			wantData, wantModTime, wantErr := deb.GetPackageChangelog(fsys, name, "hello-world", tt.pkg)

			data, modTime, err := scan.Changelog("hello-world", tt.pkg)
			assert.Equal(t, wantErr, err)
			assert.Equal(t, wantData, data)
			assert.True(t, wantModTime.Equal(modTime), "want %s, got %s", wantModTime, modTime)
		})
	}
}

// Pins what one walk of a synthetic package collects: the listing skips the
// directories, a symlinked documentation directory stops the changelog lookup
// where refusing to follow it did, and the entry it does ship is decompressed
// out of the buffer the walk kept.
func TestScanPackageWalksTheDataArchiveOnce(t *testing.T) {
	changelogTime := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	changelogText := "synthetic (1.0) unstable; urgency=medium\n\n  * Initial release.\n\n" +
		" -- Kristof Bach <crys@crys.hu>  Tue, 03 Feb 2026 04:05:06 +0000\n"

	fsys, name := writeArArchive(t, "synthetic_1.0_amd64.deb",
		arEntry{"debian-binary", []byte("2.0\n")},
		arEntry{"data.tar", writeDataTar(t,
			tarEntry{name: "./usr/share/doc/", modTime: changelogTime, dir: true},
			tarEntry{name: "./usr/share/payload", data: []byte("payload"), modTime: changelogTime},
			tarEntry{
				name:    "./usr/share/doc/synthetic/changelog.Debian.gz",
				data:    gzipBytes(t, []byte(changelogText)),
				modTime: changelogTime,
			},
			tarEntry{
				name:     "./usr/share/doc/synthetic-dbgsym",
				linkname: "synthetic",
				modTime:  changelogTime,
			},
		)})

	scan, err := deb.ScanPackage(fsys, name)
	require.NoError(t, err)

	assert.Equal(t, []string{
		"usr/share/doc/synthetic-dbgsym",
		"usr/share/doc/synthetic/changelog.Debian.gz",
		"usr/share/payload",
	}, scan.Contents)

	changelog, modTime, err := scan.Changelog("synthetic", "synthetic")
	require.NoError(t, err)
	assert.Equal(t, changelogText, string(changelog))
	assert.True(t, changelogTime.Equal(modTime), "want %s, got %s", changelogTime, modTime)

	// The symlinked documentation directory is still what stops the dbgsym from
	// falling through to the source package's changelog.
	_, _, err = scan.Changelog("synthetic", "synthetic-dbgsym")
	assert.ErrorIs(t, err, deb.ErrChangelogSymlink)
}

// Pins the fall-through an empty changelog gets: a package shipping a placeholder
// of its own is described by the source package's changelog instead.
func TestScanChangelogSkipsAnEmptyCandidate(t *testing.T) {
	sourceTime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	changelogText := "hello-world (1.0) unstable; urgency=medium\n"

	fsys, name := writeArArchive(t, "empty-candidate.deb",
		arEntry{"debian-binary", []byte("2.0\n")},
		arEntry{"data.tar", writeDataTar(t,
			tarEntry{
				name:    "./usr/share/doc/hello-world-udeb/changelog.gz",
				data:    gzipBytes(t, nil),
				modTime: sourceTime.Add(time.Hour),
			},
			tarEntry{
				name:    "./usr/share/doc/hello-world/changelog.gz",
				data:    gzipBytes(t, []byte(changelogText)),
				modTime: sourceTime,
			},
		)})

	scan, err := deb.ScanPackage(fsys, name)
	require.NoError(t, err)

	data, modTime, err := scan.Changelog("hello-world", "hello-world-udeb")
	require.NoError(t, err)

	assert.Equal(t, changelogText, string(data))
	assert.True(t, sourceTime.Equal(modTime), "want %s, got %s", sourceTime, modTime)
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	w := gzip.NewWriter(&buf)
	_, err := w.Write(body)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

type tarEntry struct {
	name     string
	data     []byte
	linkname string
	dir      bool
	modTime  time.Time
}

func writeDataTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			ModTime:  entry.modTime,
			Size:     int64(len(entry.data)),
			Typeflag: tar.TypeReg,
		}

		switch {
		case entry.dir:
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		case entry.linkname != "":
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = entry.linkname
			hdr.Size = 0
		}

		require.NoError(t, tw.WriteHeader(hdr))

		if hdr.Typeflag == tar.TypeReg {
			_, err := tw.Write(entry.data)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())

	return buf.Bytes()
}
