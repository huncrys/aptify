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

package repo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"oaklab.hu/debian/deb822/types/dependency"
	"oaklab.hu/debian/deb822/types/version"
)

// TestChangelogPathForPackage pins the path the Changelogs URL in the Release
// file resolves to. A changelog belongs to the source package, so it is named
// from the source and its version, and the epoch is stripped - the same shape
// the Debian archive serves.
func TestChangelogPathForPackage(t *testing.T) {
	sourceVersion := version.MustParse("2.0-1")
	epochSourceVersion := version.MustParse("3:2.0-1")

	for _, tc := range []struct {
		name      string
		component string
		pkgName   string
		version   string
		arch      string
		source    *dependency.Source
		want      string
	}{
		{
			// With no Source field the binary package is its own source.
			name:      "no source package",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			want:      "main/h/hello-world/hello-world_1.0.changelog",
		},
		{
			// Two binaries of one source share a single changelog file, which
			// is why the binary name appears nowhere in the path.
			name:      "named after the source package, not the binary",
			component: "main",
			pkgName:   "hello-world-dbgsym",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "hello-world"},
			want:      "main/h/hello-world/hello-world_1.0.changelog",
		},
		{
			// A source version differing from the binary's is what the
			// changelog is actually written at.
			name:      "the source version wins over the binary version",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "hello-world", Version: &sourceVersion},
			want:      "main/h/hello-world/hello-world_2.0-1.changelog",
		},
		{
			// The epoch is not part of the file name, so a package that gains
			// one keeps the same changelog path.
			name:      "the epoch is stripped from the binary version",
			component: "main",
			pkgName:   "hello-world",
			version:   "2:1.0-1",
			arch:      "amd64",
			want:      "main/h/hello-world/hello-world_1.0-1.changelog",
		},
		{
			name:      "the epoch is stripped from the source version",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "hello-world", Version: &epochSourceVersion},
			want:      "main/h/hello-world/hello-world_2.0-1.changelog",
		},
		{
			name:      "lib prefix from the package name",
			component: "main",
			pkgName:   "libhello",
			version:   "1.0",
			arch:      "amd64",
			want:      "main/libh/libhello/libhello_1.0.changelog",
		},
		{
			name:      "lib prefix from the source package",
			component: "main",
			pkgName:   "libhello-dev",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "libhello"},
			want:      "main/libh/libhello/libhello_1.0.changelog",
		},
		{
			// A Source carrying only a version is not a rename.
			name:      "source without a name falls back to the package name",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Version: &sourceVersion},
			want:      "main/h/hello-world/hello-world_1.0.changelog",
		},
		{
			name:      "whitespace around the package name is trimmed",
			component: "main",
			pkgName:   " hello-world ",
			version:   "1.0",
			arch:      "amd64",
			want:      "main/h/hello-world/hello-world_1.0.changelog",
		},
		{
			// The architecture is not in the path either: every architecture of
			// a version resolves to the one file.
			name:      "the architecture does not name the file",
			component: "main",
			pkgName:   "hello-world",
			version:   "3.0",
			arch:      "all",
			want:      "main/h/hello-world/hello-world_3.0.changelog",
		},
		{
			name:      "non default component",
			component: "contrib",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			want:      "contrib/h/hello-world/hello-world_1.0.changelog",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := testPackage(tc.pkgName, tc.version, tc.arch)
			pkg.Source = tc.source

			assert.Equal(t, tc.want, changelogPathForPackage(tc.component, &pkg))
		})
	}
}

// TestChangelogPathForPackageIgnoresArchitecture pins the consequence
// writeChangelogs relies on to write one file per source version: the path is
// the deduplication key, so every architecture of a version maps onto it.
func TestChangelogPathForPackageIgnoresArchitecture(t *testing.T) {
	amd64 := testPackage("hello-world", "1.0", "amd64")
	arm64 := testPackage("hello-world", "1.0", "arm64")

	assert.Equal(t,
		changelogPathForPackage("main", &amd64),
		changelogPathForPackage("main", &arm64))
}
