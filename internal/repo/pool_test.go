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

// TestPoolPathForPackage pins the standard Debian pool layout the copy targets:
// the directory is the source package's, prefixed by its first letter or by
// lib? for a lib*, while the file itself is named after the binary package.
func TestPoolPathForPackage(t *testing.T) {
	sourceVersion := version.MustParse("2.0")

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
			name:      "no source package",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			want:      "pool/main/h/hello-world/hello-world_1.0_amd64.deb",
		},
		{
			// lib* packages get a four character prefix, so the pool does not
			// grow one enormous l/ directory.
			name:      "lib prefix from the package name",
			component: "main",
			pkgName:   "libhello",
			version:   "1.0",
			arch:      "amd64",
			want:      "pool/main/libh/libhello/libhello_1.0_amd64.deb",
		},
		{
			// The source package names the directory, which is what puts a
			// dbgsym next to the binary it belongs to.
			name:      "source package names the directory",
			component: "main",
			pkgName:   "hello-world-dbgsym",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "hello-world"},
			want:      "pool/main/h/hello-world/hello-world-dbgsym_1.0_amd64.deb",
		},
		{
			// The prefix follows the source, not the binary package.
			name:      "lib prefix from the source package",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "libhello"},
			want:      "pool/main/libh/libhello/hello-world_1.0_amd64.deb",
		},
		{
			// A Source carrying only a version is not a rename.
			name:      "source without a name falls back to the package name",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Version: &sourceVersion},
			want:      "pool/main/h/hello-world/hello-world_1.0_amd64.deb",
		},
		{
			// The source version never names the pool file: the file is the
			// binary package, at the binary package's version.
			name:      "source version does not rename the file",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			source:    &dependency.Source{Name: "hello-world", Version: &sourceVersion},
			want:      "pool/main/h/hello-world/hello-world_1.0_amd64.deb",
		},
		{
			name:      "architecture all",
			component: "main",
			pkgName:   "hello-world",
			version:   "3.0",
			arch:      "all",
			want:      "pool/main/h/hello-world/hello-world_3.0_all.deb",
		},
		{
			name:      "non default component",
			component: "contrib",
			pkgName:   "hello-world",
			version:   "1.0",
			arch:      "amd64",
			want:      "pool/contrib/h/hello-world/hello-world_1.0_amd64.deb",
		},
		{
			// Control fields arrive with their leading space still attached.
			name:      "whitespace around the package name is trimmed",
			component: "main",
			pkgName:   " hello-world ",
			version:   "1.0",
			arch:      "amd64",
			want:      "pool/main/h/hello-world/hello-world_1.0_amd64.deb",
		},
		{
			// Unlike the changelog path, the pool file keeps the epoch.
			name:      "the epoch is kept in the file name",
			component: "main",
			pkgName:   "hello-world",
			version:   "2:1.0-1",
			arch:      "amd64",
			want:      "pool/main/h/hello-world/hello-world_2:1.0-1_amd64.deb",
		},
		{
			name:      "a native version keeps its revision",
			component: "main",
			pkgName:   "hello-world",
			version:   "1.0-2",
			arch:      "amd64",
			want:      "pool/main/h/hello-world/hello-world_1.0-2_amd64.deb",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkg := testPackage(tc.pkgName, tc.version, tc.arch)
			pkg.Source = tc.source

			assert.Equal(t, tc.want, poolPathForPackage(tc.component, &pkg))
		})
	}
}
