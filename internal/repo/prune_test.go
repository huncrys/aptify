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
	"oaklab.hu/debian/deb822/types/arch"
	"oaklab.hu/debian/deb822/types/version"
)

// testPackage builds the one package surplusVersions actually looks at: name,
// version and architecture are all Compare orders by.
func testPackage(name, pkgVersion, architecture string) types.Package {
	return types.Package{
		Name:         name,
		Version:      version.MustParse(pkgVersion),
		Architecture: arch.MustParse(architecture),
	}
}

// versionsByArch builds the by-architecture map surplusVersions takes, in the
// shape prune() assembles it: one entry per architecture, holding that
// architecture's own versions only.
func versionsByArch(name string, versionsForArch map[string][]string) map[string][]types.Package {
	packages := make(map[string][]types.Package, len(versionsForArch))
	for architecture, versions := range versionsForArch {
		for _, pkgVersion := range versions {
			packages[architecture] = append(packages[architecture], testPackage(name, pkgVersion, architecture))
		}
	}

	return packages
}

// packageKeys renders packages as "version/architecture", which is exactly the
// identity surplusVersions itself keys removals by.
func packageKeys(packages []types.Package) []string {
	var keys []string
	for _, pkg := range packages {
		keys = append(keys, pkg.Version.String()+"/"+pkg.Architecture.String())
	}

	return keys
}

// TestSurplusVersions pins how max_versions is judged: from the client's side
// of the fold. An architecture `all` package is in every architecture's indice,
// so it competes with each architecture's own versions and is only surplus once
// it is surplus for every architecture publishing it.
func TestSurplusVersions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		versions    map[string][]string
		maxVersions int
		want        []string
	}{
		{
			// The plain case: one architecture, oldest by dpkg order goes.
			name:        "single architecture drops the oldest",
			versions:    map[string][]string{"amd64": {"1.0", "2.0", "3.0"}},
			maxVersions: 2,
			want:        []string{"1.0/amd64"},
		},
		{
			// Removals come back oldest first, as many as it takes.
			name:        "single architecture drops every surplus version",
			versions:    map[string][]string{"amd64": {"1.0", "2.0", "3.0"}},
			maxVersions: 1,
			want:        []string{"1.0/amd64", "2.0/amd64"},
		},
		{
			// dpkg version order, not string order: an epoch outranks
			// everything without one.
			name:        "epoch outranks a higher version number",
			versions:    map[string][]string{"amd64": {"1:1.0", "2.0"}},
			maxVersions: 1,
			want:        []string{"2.0/amd64"},
		},
		{
			// amd64 is over max once `all` folds in, arm64 is not. There is a
			// single entry to keep or drop, so it is kept.
			name: "arch all surplus for one architecture only is kept",
			versions: map[string][]string{
				"all":   {"1.0"},
				"amd64": {"2.0", "3.0"},
				"arm64": {"1.5"},
			},
			maxVersions: 2,
			want:        nil,
		},
		{
			// Surplus for every architecture publishing it, so it goes - and it
			// is one entry, so it comes back once rather than once per
			// architecture.
			name: "arch all surplus everywhere is dropped once",
			versions: map[string][]string{
				"all":   {"1.0"},
				"amd64": {"2.0", "3.0"},
				"arm64": {"2.0", "3.0"},
			},
			maxVersions: 2,
			want:        []string{"1.0/all"},
		},
		{
			// The fold works the other way too: a newer `all` pushes an
			// architecture's own oldest version out.
			name: "a newer arch all version pushes out an architecture's own",
			versions: map[string][]string{
				"all":   {"3.0"},
				"amd64": {"1.0", "2.0"},
			},
			maxVersions: 2,
			want:        []string{"1.0/amd64"},
		},
		{
			// Same version in both: Compare falls through to the architecture
			// name, so `all` sorts below amd64 and is the one over the line.
			name: "arch all ties with an architecture's own version",
			versions: map[string][]string{
				"all":   {"1.0"},
				"amd64": {"1.0", "2.0"},
			},
			maxVersions: 2,
			want:        []string{"1.0/all"},
		},
		{
			// Nothing to fold into, so `all` is an architecture of its own and
			// its versions compete only with each other.
			name:        "component whose only architecture is all",
			versions:    map[string][]string{"all": {"1.0", "2.0", "3.0"}},
			maxVersions: 2,
			want:        []string{"1.0/all"},
		},
		{
			// Each architecture is judged on its own list.
			name: "every architecture drops its own oldest",
			versions: map[string][]string{
				"amd64": {"1.0", "2.0"},
				"arm64": {"1.0", "2.0"},
			},
			maxVersions: 1,
			want:        []string{"1.0/amd64", "1.0/arm64"},
		},
		{
			name:        "max versions equal to the version count",
			versions:    map[string][]string{"amd64": {"1.0", "2.0"}},
			maxVersions: 2,
			want:        nil,
		},
		{
			name:        "max versions above the version count",
			versions:    map[string][]string{"amd64": {"1.0", "2.0"}},
			maxVersions: 5,
			want:        nil,
		},
		{
			// max_versions is a uint and prune() skips a component set to 0
			// before it ever gets here, so this is what the arithmetic does
			// rather than a configuration anyone can reach: keep nothing.
			name:        "zero max versions is unreachable and would drop everything",
			versions:    map[string][]string{"amd64": {"1.0", "2.0"}},
			maxVersions: 0,
			want:        []string{"1.0/amd64", "2.0/amd64"},
		},
		{
			// Also unreachable - a negative only arises from an overflowing
			// uint conversion - and it drops everything just the same.
			name:        "negative max versions is unreachable and would drop everything",
			versions:    map[string][]string{"amd64": {"1.0", "2.0"}},
			maxVersions: -1,
			want:        []string{"1.0/amd64", "2.0/amd64"},
		},
		{
			name:        "no versions at all",
			versions:    map[string][]string{},
			maxVersions: 2,
			want:        nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := surplusVersions(versionsByArch("hello-world", tc.versions), tc.maxVersions)

			assert.Equal(t, tc.want, packageKeys(got))
		})
	}
}

// TestSurplusVersionsKeepsArchAllOverMaxVersions pins the consequence CLAUDE.md
// calls the honest outcome: keeping an `all` version another architecture still
// needs leaves the crowded architecture publishing more than max_versions.
func TestSurplusVersionsKeepsArchAllOverMaxVersions(t *testing.T) {
	const maxVersions = 2

	versions := versionsByArch("hello-world", map[string][]string{
		"all":   {"1.0"},
		"amd64": {"2.0", "3.0"},
		"arm64": {"1.5"},
	})

	removals := surplusVersions(versions, maxVersions)
	require.Empty(t, removals, "the arch all version arm64 still needs was dropped")

	// What each architecture publishes afterwards is its own versions plus the
	// folded in `all` ones.
	published := len(versions["amd64"]) + len(versions["all"])
	assert.Greater(t, published, maxVersions,
		"amd64 should be left over max_versions, which is the price of keeping the shared entry")
}

// TestSurplusVersionsReturnsSharedArchAllOnce guards the miscount the pool
// garbage collector used to trip over: an `all` package is listed once per
// architecture but removed once, so it must come back as a single entry.
func TestSurplusVersionsReturnsSharedArchAllOnce(t *testing.T) {
	removals := surplusVersions(versionsByArch("hello-world", map[string][]string{
		"all":     {"1.0"},
		"amd64":   {"2.0", "3.0"},
		"arm64":   {"2.0", "3.0"},
		"riscv64": {"2.0", "3.0"},
	}), 2)

	require.Len(t, removals, 1)
	assert.Equal(t, "1.0", removals[0].Version.String())
	assert.Equal(t, "all", removals[0].Architecture.String())
}
