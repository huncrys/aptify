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

package deb_test

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// Pins the exact paths that end up in a Contents indice: directories are
// dropped, the leading "./" of the tar member names is stripped, and a symlink
// (the dbgsym doc directory) is listed like any other non-directory entry.
func TestGetPackageContents(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []string
	}{
		{
			name: "binary package",
			file: "hello-world_1.0_amd64.deb",
			want: []string{
				"usr/bin/hello",
				"usr/share/doc/hello-world/changelog.gz",
				"usr/share/doc/hello-world/copyright",
			},
		},
		{
			name: "architecture all package",
			file: "hello-world_3.0_all.deb",
			want: []string{
				"usr/bin/hello",
				"usr/share/doc/hello-world/changelog.gz",
				"usr/share/doc/hello-world/copyright",
			},
		},
		{
			name: "debug symbols package lists its symlinked doc directory",
			file: "hello-world-dbgsym_1.0_amd64.deb",
			want: []string{
				"usr/lib/debug/.build-id/df/17f3770bc042857d4c6f417eb1b2b4cc6e47c9.debug",
				"usr/share/doc/hello-world-dbgsym",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, err := deb.GetPackageContents(fixture(tt.file))
			require.NoError(t, err)

			assert.Equal(t, tt.want, contents)
		})
	}
}

// Pins that the listing is architecture specific where the payload is: the two
// builds of the same version share their doc paths but not the binary's build id.
func TestGetPackageContentsPerArchitecture(t *testing.T) {
	amd64, err := deb.GetPackageContents(fixture("hello-world-dbgsym_1.0_amd64.deb"))
	require.NoError(t, err)

	arm64, err := deb.GetPackageContents(fixture("hello-world-dbgsym_1.0_arm64.deb"))
	require.NoError(t, err)

	assert.NotEqual(t, amd64, arm64)
	assert.Contains(t, arm64, "usr/lib/debug/.build-id/d2/b4acc047f33d56cfcc12c8f6b59d38e49ac96a.debug")
	assert.Contains(t, arm64, "usr/share/doc/hello-world-dbgsym")
}

// Pins the failure modes, which mirror GetMetadata's: the archive guard runs
// before anything is read out of the data tarball.
func TestGetPackageContentsErrors(t *testing.T) {
	t.Run("not a debian package", func(t *testing.T) {
		_, err := deb.GetPackageContents(fixture("hello-world_1.0.dsc"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open archive")
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := deb.GetPackageContents(fixture("no-such-package_9.9_amd64.deb"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open package file")
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("unsupported package version", func(t *testing.T) {
		path := writeArArchive(t, "unsupported.deb", arEntry{"debian-binary", []byte("3.0\n")})

		_, err := deb.GetPackageContents(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported debian package version")
	})

	t.Run("missing data archive", func(t *testing.T) {
		path := writeArArchive(t, "no-data.deb",
			arEntry{"debian-binary", []byte("2.0\n")},
			arEntry{"control.tar", []byte("not really a tar")})

		_, err := deb.GetPackageContents(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find data archive")
	})
}
