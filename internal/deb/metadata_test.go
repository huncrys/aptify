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
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// fixtureDir is the checked-in set of hello-world packages the whole package is
// tested against.
const fixtureDir = "../../testdata/package"

// fixture addresses a checked-in package the way the readers take one: the
// filesystem it lives on, and its name on that filesystem.
func fixture(name string) (fs.FS, string) {
	return os.DirFS(fixtureDir), name
}

// fixturePath is the local path of the same package, for the tests that have
// to stat it.
func fixturePath(name string) string {
	return filepath.Join(fixtureDir, name)
}

// Pins the control fields GetMetadata lifts out of a .deb: the identity fields
// the pool layout and the indices are keyed by, and the fact that architecture
// "all" is reported verbatim rather than mapped to a concrete architecture.
func TestGetMetadata(t *testing.T) {
	tests := []struct {
		name             string
		file             string
		wantName         string
		wantVersion      string
		wantArchitecture string
		wantSection      string
		wantPriority     string
		wantSource       string
		wantInstalled    int
	}{
		{
			name:             "binary package",
			file:             "hello-world_1.0_amd64.deb",
			wantName:         "hello-world",
			wantVersion:      "1.0",
			wantArchitecture: "amd64",
			wantSection:      "utils",
			wantPriority:     "optional",
			wantInstalled:    24,
		},
		{
			name:             "other architecture",
			file:             "hello-world_2.0_arm64.deb",
			wantName:         "hello-world",
			wantVersion:      "2.0",
			wantArchitecture: "arm64",
			wantSection:      "utils",
			wantPriority:     "optional",
			wantInstalled:    76,
		},
		{
			name:             "architecture all",
			file:             "hello-world_3.0_all.deb",
			wantName:         "hello-world",
			wantVersion:      "3.0",
			wantArchitecture: "all",
			wantSection:      "utils",
			wantPriority:     "optional",
			wantInstalled:    10,
		},
		{
			name:             "debug symbols package carries a Source field",
			file:             "hello-world-dbgsym_1.0_amd64.deb",
			wantName:         "hello-world-dbgsym",
			wantVersion:      "1.0",
			wantArchitecture: "amd64",
			wantSection:      "debug",
			wantPriority:     "optional",
			wantSource:       "hello-world",
			wantInstalled:    18,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, err := deb.GetMetadata(fixture(tt.file))
			require.NoError(t, err)
			require.NotNil(t, pkg)

			assert.Equal(t, tt.wantName, pkg.Name)
			assert.Equal(t, tt.wantVersion, pkg.Version.String())
			assert.Equal(t, tt.wantArchitecture, pkg.Architecture.String())
			assert.Equal(t, tt.wantSection, pkg.Section)
			assert.Equal(t, tt.wantPriority, pkg.Priority)
			assert.Equal(t, "Damian Peckett <damian@pecke.tt>", pkg.Maintainer)
			assert.NotEmpty(t, pkg.Description)

			if tt.wantSource == "" {
				assert.Nil(t, pkg.Source)
			} else {
				require.NotNil(t, pkg.Source)
				assert.Equal(t, tt.wantSource, pkg.Source.Name)
			}

			require.NotNil(t, pkg.InstalledSize)
			assert.Equal(t, tt.wantInstalled, *pkg.InstalledSize)
		})
	}
}

// Pins the shape of the description: the short description is the first line and
// the long description follows, so a caller can split on the newline.
func TestGetMetadataDescription(t *testing.T) {
	pkg, err := deb.GetMetadata(fixture("hello-world_1.0_amd64.deb"))
	require.NoError(t, err)

	assert.Equal(t,
		"A simple Hello World program\nThis is a minimal Debian package that contains a Hello World binary.\n",
		pkg.Description)
}

// Pins that GetMetadata reports the control stanza only: the archive-level fields
// are the caller's job to fill in once the package has been copied into the pool.
func TestGetMetadataLeavesArchiveFieldsUnset(t *testing.T) {
	pkg, err := deb.GetMetadata(fixture("hello-world_1.0_amd64.deb"))
	require.NoError(t, err)

	assert.Empty(t, pkg.Filename)
	assert.Zero(t, pkg.Size)
	assert.Empty(t, pkg.SHA256)
	assert.Empty(t, pkg.MD5sum)
	assert.Empty(t, pkg.SHA1)
	assert.Empty(t, pkg.DescriptionMD5)
}

// Pins the failure modes: a file that is not an ar archive is rejected, and a
// missing file surfaces an error the os.IsNotExist family recognises.
func TestGetMetadataErrors(t *testing.T) {
	t.Run("not a debian package", func(t *testing.T) {
		_, err := deb.GetMetadata(fixture("hello-world_1.0.dsc"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open archive")
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := deb.GetMetadata(fixture("no-such-package_9.9_amd64.deb"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open package file")
		assert.True(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("unsupported package version", func(t *testing.T) {
		_, err := deb.GetMetadata(writeArArchive(t, "unsupported.deb",
			arEntry{"debian-binary", []byte("3.0\n")}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported debian package version")
	})

	t.Run("missing control archive", func(t *testing.T) {
		_, err := deb.GetMetadata(writeArArchive(t, "no-control.deb",
			arEntry{"debian-binary", []byte("2.0\n")},
			arEntry{"data.tar", []byte("not really a tar")}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find control archive")
	})
}

type arEntry struct {
	name string
	data []byte
}

// writeArArchive builds a minimal ar archive so the guards that reject a
// malformed .deb can be exercised without a fixture on disk.
func writeArArchive(t *testing.T, name string, entries ...arEntry) (fs.FS, string) {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	for _, entry := range entries {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n",
			entry.name, 0, 0, 0, "100644", len(entry.data))
		buf.Write(entry.data)
		if len(entry.data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644))

	return os.DirFS(dir), name
}
