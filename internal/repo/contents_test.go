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
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/deb822/types"
)

// TestLatestPackages pins the version Contents describes: the newest one
// published for the architecture, which is the one a client would install.
// Contents has no version column, so a name can only be described once.
func TestLatestPackages(t *testing.T) {
	for _, tc := range []struct {
		name     string
		packages []types.Package
		want     map[string]string
	}{
		{
			name:     "no packages",
			packages: nil,
			want:     map[string]string{},
		},
		{
			// Input order does not matter, only dpkg version order.
			name: "newest version wins, oldest first",
			packages: []types.Package{
				testPackage("hello-world", "1.0", "amd64"),
				testPackage("hello-world", "2.0", "amd64"),
			},
			want: map[string]string{"hello-world": "2.0/amd64"},
		},
		{
			name: "newest version wins, newest first",
			packages: []types.Package{
				testPackage("hello-world", "2.0", "amd64"),
				testPackage("hello-world", "1.0", "amd64"),
			},
			want: map[string]string{"hello-world": "2.0/amd64"},
		},
		{
			name: "epoch outranks a higher version number",
			packages: []types.Package{
				testPackage("hello-world", "2.0", "amd64"),
				testPackage("hello-world", "1:1.0", "amd64"),
			},
			want: map[string]string{"hello-world": "1:1.0/amd64"},
		},
		{
			// Every name is judged on its own.
			name: "one winner per name",
			packages: []types.Package{
				testPackage("hello-world", "1.0", "amd64"),
				testPackage("hello-world", "2.0", "amd64"),
				testPackage("goodbye-world", "0.1", "amd64"),
			},
			want: map[string]string{
				"hello-world":   "2.0/amd64",
				"goodbye-world": "0.1/amd64",
			},
		},
		{
			// The architecture `all` build folded into this architecture's
			// indice competes with the architecture's own packages, and loses
			// on version like anything else.
			name: "an arch all package wins on version",
			packages: []types.Package{
				testPackage("hello-world", "1.0", "amd64"),
				testPackage("hello-world", "3.0", "all"),
			},
			want: map[string]string{"hello-world": "3.0/all"},
		},
		{
			// Compare falls through to the architecture name when the versions
			// tie, so the winner is the same whichever order they arrive in -
			// and it is not the arch all one.
			name: "a tie is broken by architecture, all first",
			packages: []types.Package{
				testPackage("hello-world", "1.0", "all"),
				testPackage("hello-world", "1.0", "amd64"),
			},
			want: map[string]string{"hello-world": "1.0/amd64"},
		},
		{
			name: "a tie is broken by architecture, all last",
			packages: []types.Package{
				testPackage("hello-world", "1.0", "amd64"),
				testPackage("hello-world", "1.0", "all"),
			},
			want: map[string]string{"hello-world": "1.0/amd64"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := latestPackages(tc.packages)

			keys := make(map[string]string, len(got))
			for name, pkg := range got {
				keys[name] = pkg.Version.String() + "/" + pkg.Architecture.String()
			}

			assert.Equal(t, tc.want, keys)
		})
	}
}

// TestLatestPackagesKeepsTheFirstOfEqualPackages pins the tie-break for
// packages Compare cannot tell apart at all: the first one seen is kept, so a
// second stanza for the same name, version and architecture does not displace
// the file already chosen.
func TestLatestPackagesKeepsTheFirstOfEqualPackages(t *testing.T) {
	first := testPackage("hello-world", "1.0", "amd64")
	first.Filename = "pool/main/h/hello-world/hello-world_1.0_amd64.deb"

	second := testPackage("hello-world", "1.0", "amd64")
	second.Filename = "pool/contrib/h/hello-world/hello-world_1.0_amd64.deb"

	got := latestPackages([]types.Package{first, second})

	require.Contains(t, got, "hello-world")
	assert.Equal(t, first.Filename, got["hello-world"].Filename)
}

// TestContentsIndiceNames pins that the uncompressed name is published too. apt
// resolves a target by its uncompressed key in the Release file and only then
// picks a compressed variant, so an indice listed as .gz alone is never
// acquired - which is what kept apt-file from seeing Contents.
func TestContentsIndiceNames(t *testing.T) {
	for _, tc := range []struct {
		architecture string
		want         []string
	}{
		{"amd64", []string{"Contents-amd64", "Contents-amd64.gz"}},
		{"arm64", []string{"Contents-arm64", "Contents-arm64.gz"}},
		{"all", []string{"Contents-all", "Contents-all.gz"}},
	} {
		t.Run(tc.architecture, func(t *testing.T) {
			assert.Equal(t, tc.want, contentsIndiceNames(tc.architecture))
		})
	}
}
