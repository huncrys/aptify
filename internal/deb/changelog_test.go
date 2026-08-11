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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// Pins the happy path: the gzipped changelog is decompressed, the newest entry
// comes first, and the returned time is the archive member's mtime (which is
// what dates the published file) rather than the time of the build.
func TestGetPackageChangelog(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		pkg         string
		file        string
		wantPrefix  string
		wantEntries int
		wantModTime time.Time
	}{
		{
			name:        "single entry",
			source:      "hello-world",
			pkg:         "hello-world",
			file:        "hello-world_1.0_amd64.deb",
			wantPrefix:  "hello-world (1.0) unstable; urgency=medium",
			wantEntries: 1,
			wantModTime: time.Date(2024, 7, 14, 9, 34, 56, 0, time.FixedZone("CEST", 2*60*60)),
		},
		{
			name:        "newest entry first",
			source:      "hello-world",
			pkg:         "hello-world",
			file:        "hello-world_3.0_all.deb",
			wantPrefix:  "hello-world (3.0) unstable; urgency=medium",
			wantEntries: 3,
			wantModTime: time.Date(2026, 3, 27, 6, 53, 46, 0, time.FixedZone("CET", 1*60*60)),
		},
		{
			name:        "falls back to the source package's doc directory",
			source:      "hello-world",
			pkg:         "hello-world-udeb",
			file:        "hello-world_1.0_amd64.deb",
			wantPrefix:  "hello-world (1.0) unstable; urgency=medium",
			wantEntries: 1,
			wantModTime: time.Date(2024, 7, 14, 9, 34, 56, 0, time.FixedZone("CEST", 2*60*60)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys, name := fixture(tt.file)

			data, modTime, err := deb.GetPackageChangelog(fsys, name, tt.source, tt.pkg)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			assert.True(t, strings.HasPrefix(string(data), tt.wantPrefix),
				"changelog starts with %q", firstLine(string(data)))
			assert.Equal(t, tt.wantEntries, strings.Count(string(data), "hello-world ("))
			assert.False(t, modTime.IsZero())
			assert.True(t, tt.wantModTime.Equal(modTime), "want %s, got %s", tt.wantModTime, modTime)
		})
	}
}

// Pins the ErrChangelogSymlink contract: the dbgsym packages ship
// usr/share/doc/hello-world-dbgsym as a symlink to the parent package's doc
// directory, which the walker refuses to follow. There is still nothing to
// extract, so the caller gets the same usable timestamp it gets for a package
// shipping no changelog at all, and writes the same placeholder.
func TestGetPackageChangelogSymlinkedDocDirectory(t *testing.T) {
	for _, file := range []string{
		"hello-world-dbgsym_1.0_amd64.deb",
		"hello-world-dbgsym_1.0_arm64.deb",
		"hello-world-dbgsym_2.0_amd64.deb",
		"hello-world-dbgsym_2.0_arm64.deb",
	} {
		t.Run(file, func(t *testing.T) {
			info, err := os.Stat(fixturePath(file))
			require.NoError(t, err)

			fsys, name := fixture(file)

			data, modTime, err := deb.GetPackageChangelog(fsys, name, "hello-world", "hello-world-dbgsym")
			require.Error(t, err)

			assert.True(t, errors.Is(err, deb.ErrChangelogSymlink), "got %v", err)
			assert.Nil(t, data)
			assert.True(t, info.ModTime().Equal(modTime), "want the .deb mtime %s, got %s", info.ModTime(), modTime)

			// The package itself read fine, which is what tells the caller a
			// placeholder is the right answer.
			assert.False(t, errors.Is(err, deb.ErrPackageUnreadable))
			assert.False(t, os.IsNotExist(err))
		})
	}
}

// Pins the contract writeChangelogs in internal/repo depends on for its
// placeholder fallback: a package with no changelog inside the archive yields an
// error that os.IsNotExist reports true for, plus a usable timestamp (the .deb's
// own mtime), which is what dates the synthetic entry.
func TestGetPackageChangelogNotFound(t *testing.T) {
	info, err := os.Stat(fixturePath("hello-world_1.0_amd64.deb"))
	require.NoError(t, err)

	fsys, name := fixture("hello-world_1.0_amd64.deb")

	data, modTime, err := deb.GetPackageChangelog(fsys, name, "", "not-a-shipped-name")
	require.Error(t, err)

	assert.True(t, os.IsNotExist(err), "got %v", err)
	assert.True(t, errors.Is(err, os.ErrNotExist), "got %v", err)
	assert.False(t, errors.Is(err, deb.ErrPackageUnreadable))
	assert.Nil(t, data)
	assert.False(t, modTime.IsZero())
	assert.True(t, info.ModTime().Equal(modTime), "want the .deb mtime %s, got %s", info.ModTime(), modTime)
}

// Pins that a broken package reports a plain error, so the placeholder fallback
// is not taken for something that is not a missing changelog.
func TestGetPackageChangelogErrors(t *testing.T) {
	t.Run("not a debian package", func(t *testing.T) {
		fsys, name := fixture("hello-world_1.0.dsc")

		_, _, err := deb.GetPackageChangelog(fsys, name, "hello-world", "hello-world")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open archive")
		assert.False(t, os.IsNotExist(err))
	})

	// A package that cannot be opened at all is reported apart from one that
	// ships no changelog, so that a vanished pool file gets no placeholder
	// claiming the version has nothing to report.
	t.Run("nonexistent file", func(t *testing.T) {
		fsys, name := fixture("no-such-package_9.9_amd64.deb")

		_, _, err := deb.GetPackageChangelog(fsys, name, "hello-world", "hello-world")
		require.Error(t, err)
		assert.True(t, errors.Is(err, deb.ErrPackageUnreadable), "got %v", err)
		assert.Contains(t, err.Error(), "package file cannot be opened")
	})

	t.Run("unsupported package version", func(t *testing.T) {
		fsys, name := writeArArchive(t, "unsupported.deb", arEntry{"debian-binary", []byte("3.0\n")})

		_, _, err := deb.GetPackageChangelog(fsys, name, "hello-world", "hello-world")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported debian package version")
	})

	t.Run("missing data archive", func(t *testing.T) {
		fsys, name := writeArArchive(t, "no-data.deb",
			arEntry{"debian-binary", []byte("2.0\n")},
			arEntry{"control.tar", []byte("not really a tar")})

		_, _, err := deb.GetPackageChangelog(fsys, name, "hello-world", "hello-world")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find data archive")
	})
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}

	return s
}
