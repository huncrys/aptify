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
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// oneOffOptions is what every one-off in these tests is given: the repository
// as a directory, the configuration it keeps its release metadata in, and the
// fixture signing key.
func oneOffOptions(t *testing.T, repoDir, confPath string) Options {
	t.Helper()

	return Options{
		FS:             repofs.NewOS(repoDir),
		ConfigPath:     confPath,
		PrivateKeyPath: testKeyPath(t),
	}
}

// mustAdd publishes local .deb files into a component, in process.
func mustAdd(t *testing.T, repoDir, confPath, release, component string, packages ...string) {
	t.Helper()

	require.NoError(t, Add(AddOptions{
		Options:   oneOffOptions(t, repoDir, confPath),
		Release:   release,
		Component: component,
		Packages:  packages,
	}))
}

// mustRemove withdraws packages from a component, in process.
func mustRemove(t *testing.T, repoDir, confPath, release, component, architecture string, selectors ...string) {
	t.Helper()

	require.NoError(t, Remove(RemoveOptions{
		Options:   oneOffOptions(t, repoDir, confPath),
		Release:   release,
		Component: component,
		Arch:      architecture,
		Selectors: selectors,
	}))
}

// TestAddPublishesIntoOneComponent pins what a one-off add does and what it
// leaves alone: the package joins the named component's indices and the pool,
// the release is republished over the new checksums, and the component that
// gained nothing keeps its indices byte for byte.
func TestAddPublishesIntoOneComponent(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, testConfig(releaseConfig(testReleaseName,
		componentConfig(testComponentName, 0, debPath(t, "hello-world_1.0_amd64.deb")),
		componentConfig("extra", 0, debPath(t, "hello-world_1.0_arm64.deb")))))

	mustBuild(t, repoDir, confPath, false, false)
	before := snapshotTree(t, repoDir)

	widget := buildTestDeb(t, t.TempDir(), debFixture{
		name: "widget", version: "1.0", architecture: "amd64",
		files: map[string]string{"usr/bin/widget": "widget\n"},
	})

	mustAdd(t, repoDir, confPath, testReleaseName, testComponentName, widget)

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"hello-world 1.0 amd64", "widget 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	assert.Contains(t,
		readContents(t, distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")),
		"usr/bin/widget")

	after := snapshotTree(t, repoDir)

	assert.Equal(t, "pool/stable/w/widget/widget_1.0_amd64.deb",
		onlyAddedUnder(t, "pool/", before, after))

	for _, name := range []string{
		distName(testReleaseName, "extra", "binary-arm64", "Packages"),
		distName(testReleaseName, "extra", "Contents-arm64"),
	} {
		assert.Equal(t, before[name], after[name], "%s was republished", name)
	}

	packagesName := distName(testReleaseName, testComponentName, "binary-amd64", "Packages")
	assert.NotEqual(t, before[packagesName], after[packagesName])

	inRelease := path.Join("dists", testReleaseName, "InRelease")
	assert.NotEqual(t, before[inRelease], after[inRelease])
}

// TestAddRespectsMaxVersions pins that a one-off add is pruned like any other
// publication: the version it puts the component over the cap with is the
// oldest, and its pool file goes with it.
func TestAddRespectsMaxVersions(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()

	widget := func(pkgVersion string) string {
		return buildTestDeb(t, sourceDir, debFixture{
			name: "widget", version: pkgVersion, architecture: "amd64",
			files: map[string]string{"usr/bin/widget": pkgVersion + "\n"},
		})
	}

	confPath := writeTestConfig(t, singleComponentConfig(2, widget("1.0"), widget("2.0")))

	mustBuild(t, repoDir, confPath, false, false)

	// Neither -r nor -C is given: the configuration has one release with one
	// component, so there is nothing else they could mean.
	mustAdd(t, repoDir, confPath, "", "", widget("3.0"))

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"widget 2.0 amd64", "widget 3.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	assert.NoFileExists(t, filepath.Join(repoDir, "pool", "stable", "w", "widget", "widget_1.0_amd64.deb"))
}

// TestRemoveByNameAndVersion pins the ordinary withdrawal: the stanza leaves
// every index, the pool file is collected, and because Contents describes the
// version a client would install, it falls back to the version that is left.
func TestRemoveByNameAndVersion(t *testing.T) {
	repoDir := t.TempDir()
	older, newer := versionedFixtures(t)

	confPath := writeTestConfig(t, singleComponentConfig(0, older, newer))

	mustBuild(t, repoDir, confPath, false, false)

	contentsPath := distPath(repoDir, testReleaseName, testComponentName, "Contents-amd64")
	require.Contains(t, readContents(t, contentsPath), "usr/share/demo/two.txt")

	mustRemove(t, repoDir, confPath, "", "", "", "demo-tool=2.0")

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"demo-tool 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	published := readContents(t, contentsPath)
	assert.Contains(t, published, "usr/share/demo/one.txt")
	assert.NotContains(t, published, "usr/share/demo/two.txt")

	assert.NoFileExists(t,
		filepath.Join(repoDir, "pool", "stable", "d", "demo-tool", "demo-tool_2.0_amd64.deb"))
	assert.FileExists(t,
		filepath.Join(repoDir, "pool", "stable", "d", "demo-tool", "demo-tool_1.0_amd64.deb"))
}

// TestRemoveMatchesEpochVersions pins that a pinned version is compared as a
// Debian version rather than as a string: the epoch is part of what the stanza
// publishes, so a selector has to carry it.
func TestRemoveMatchesEpochVersions(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()

	epoched := buildTestDeb(t, sourceDir, debFixture{
		name: "widget", version: "1:2.0-1", architecture: "amd64",
		files: map[string]string{"usr/bin/widget": "epoched\n"},
	})

	confPath := writeTestConfig(t, singleComponentConfig(0, epoched))

	mustBuild(t, repoDir, confPath, false, false)

	// The pool file drops the epoch, the stanza keeps it.
	poolPath := filepath.Join(repoDir, "pool", "stable", "w", "widget", "widget_2.0-1_amd64.deb")
	require.FileExists(t, poolPath)

	require.ErrorContains(t, Remove(RemoveOptions{
		Options:   oneOffOptions(t, repoDir, confPath),
		Selectors: []string{"widget=2.0-1"},
	}), "matches no package")

	mustRemove(t, repoDir, confPath, "", "", "", "widget=1:2.0-1")

	verifyRepo(t, repoDir, testReleaseName)

	assert.Empty(t, packagesIn(t, repoDir, "amd64"))
	assert.NoFileExists(t, poolPath)
}

// TestRemoveByNameDropsEveryVersion pins the bare name selector, and with it
// the changelog pruning: a source nothing publishes any more keeps no
// changelog file behind.
func TestRemoveByNameDropsEveryVersion(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, changelogConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb")))

	mustBuild(t, repoDir, confPath, false, false)

	for _, pkgVersion := range []string{"1.0", "2.0"} {
		require.FileExists(t, changelogPath(repoDir, "hello-world", pkgVersion))
	}

	mustRemove(t, repoDir, confPath, "", "", "", "hello-world")

	verifyRepo(t, repoDir, testReleaseName)

	assert.Empty(t, packagesIn(t, repoDir, "amd64"))

	for _, pkgVersion := range []string{"1.0", "2.0"} {
		assert.NoFileExists(t, changelogPath(repoDir, "hello-world", pkgVersion))
		assert.NoFileExists(t, filepath.Join(repoDir, "pool", "stable", "h", "hello-world",
			"hello-world_"+pkgVersion+"_amd64.deb"))
	}
}

// TestRemoveByPackageFile pins the exact selector: a local .deb stands for the
// one stanza whose name, version and architecture it holds, and for nothing
// else the repository publishes.
func TestRemoveByPackageFile(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb"),
		debPath(t, "hello-world_2.0_arm64.deb")))

	mustBuild(t, repoDir, confPath, false, false)

	mustRemove(t, repoDir, confPath, "", "", "", debPath(t, "hello-world_2.0_amd64.deb"))

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"hello-world 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))
	assert.Equal(t, []string{"hello-world 2.0 arm64"},
		packageVersions(packagesIn(t, repoDir, "arm64")))
}

// TestRemoveKeepsAPoolFileAnotherComponentPublishes pins the pool collection
// against a .deb two components share: it is copied once and counted once per
// component, so it survives until the last of them stops listing it.
func TestRemoveKeepsAPoolFileAnotherComponentPublishes(t *testing.T) {
	repoDir := t.TempDir()

	shared := debPath(t, "hello-world_1.0_amd64.deb")
	confPath := writeTestConfig(t, testConfig(releaseConfig(testReleaseName,
		componentConfig(testComponentName, 0, shared),
		componentConfig("extra", 0, shared))))

	mustBuild(t, repoDir, confPath, false, false)

	poolPath := filepath.Join(repoDir, "pool", "stable", "h", "hello-world", "hello-world_1.0_amd64.deb")
	require.FileExists(t, poolPath)

	mustRemove(t, repoDir, confPath, testReleaseName, "extra", "", "hello-world")
	assert.FileExists(t, poolPath, "a pool file another component still publishes was collected")

	mustRemove(t, repoDir, confPath, testReleaseName, testComponentName, "", "hello-world")
	assert.NoFileExists(t, poolPath)

	verifyRepo(t, repoDir, testReleaseName)
}

// TestOneOffRejectsUnusableArguments pins that a one-off which cannot do what
// it was asked says so and publishes nothing: an unknown target, a selector
// matching nothing, and an architecture `all` package no architecture can drop
// on its own all leave the repository exactly as it was.
func TestOneOffRejectsUnusableArguments(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_3.0_all.deb")))

	mustBuild(t, repoDir, confPath, false, false)
	before := snapshotTree(t, repoDir)

	remove := func(opts RemoveOptions) error {
		opts.Options = oneOffOptions(t, repoDir, confPath)

		return Remove(opts)
	}

	t.Run("unknown release", func(t *testing.T) {
		require.ErrorContains(t, remove(RemoveOptions{
			Release:   "trixie",
			Selectors: []string{"hello-world"},
		}), `no release "trixie"`)
	})

	t.Run("unknown component", func(t *testing.T) {
		require.ErrorContains(t, remove(RemoveOptions{
			Component: "contrib",
			Selectors: []string{"hello-world"},
		}), `no component "contrib"`)
	})

	t.Run("selector matches nothing", func(t *testing.T) {
		err := remove(RemoveOptions{Selectors: []string{"absent", "hello-world=9.9"}})

		// Every miss is reported, so one run lists them all.
		require.ErrorContains(t, err, "absent matches no package")
		require.ErrorContains(t, err, "hello-world=9.9 matches no package")
	})

	t.Run("no selectors", func(t *testing.T) {
		require.ErrorContains(t, remove(RemoveOptions{}), "no packages given")
	})

	t.Run("architecture all is not removable per architecture", func(t *testing.T) {
		require.ErrorContains(t, remove(RemoveOptions{
			Arch:      "amd64",
			Selectors: []string{"hello-world"},
		}), "architecture all")
	})

	t.Run("missing package file", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), "absent.deb")

		require.Error(t, Add(AddOptions{
			Options:  oneOffOptions(t, repoDir, confPath),
			Packages: []string{absent},
		}))

		// The same path as a removal selector is a file that has to exist too,
		// rather than a package named "absent.deb".
		require.Error(t, remove(RemoveOptions{Selectors: []string{absent}}))
	})

	assert.Equal(t, before, snapshotTree(t, repoDir), "a rejected one-off changed the repository")
}

// TestOneOffKeepsTheArchitecturesAComponentPublishes pins where a run with no
// configured globs to expand reads the architectures from. A component whose
// every published stanza is architecture `all` - the fold puts one into every
// architecture's indice and the stanza records nothing about which - would read
// back as an `all` only component if the stanzas were all there was to go on,
// and the removal below would then publish binary-all and leave the real
// architectures behind, still naming a pool file it had just collected.
func TestOneOffKeepsTheArchitecturesAComponentPublishes(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(1,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_1.0_arm64.deb"),
		debPath(t, "hello-world_3.0_all.deb")))

	mustBuild(t, repoDir, confPath, false, false)

	// max_versions leaves the `all` package alone, folded into both.
	for _, architecture := range []string{"amd64", "arm64"} {
		require.Equal(t, []string{"hello-world 3.0 all"},
			packageVersions(packagesIn(t, repoDir, architecture)))
	}

	mustRemove(t, repoDir, confPath, "", "", "", "hello-world")

	verifyRepo(t, repoDir, testReleaseName)

	assert.NoDirExists(t, distPath(repoDir, testReleaseName, testComponentName, "binary-all"))

	for _, architecture := range []string{"amd64", "arm64"} {
		assert.Empty(t, packagesIn(t, repoDir, architecture),
			"binary-%s still publishes a withdrawn package", architecture)
	}

	assert.NoFileExists(t,
		filepath.Join(repoDir, "pool", "stable", "h", "hello-world", "hello-world_3.0_all.deb"))
}

// TestBuildAfterOneOffChangeTouchesNothing pins that the two ways of publishing
// agree about the result: a build run over a repository a one-off just changed
// finds nothing to do, in either direction.
func TestBuildAfterOneOffChangeTouchesNothing(t *testing.T) {
	repoDir := t.TempDir()

	// The added package is deliberately outside the configured globs, which is
	// what makes the removal below stick.
	confPath := writeTestConfig(t, singleComponentConfig(0, debPath(t, "hello-world_1.0_amd64.deb")))

	mustBuild(t, repoDir, confPath, false, false)

	mustAdd(t, repoDir, confPath, "", "", debPath(t, "hello-world_2.0_amd64.deb"))
	afterAdd := snapshotTree(t, repoDir)

	mustBuild(t, repoDir, confPath, false, false)
	require.Equal(t, afterAdd, snapshotTree(t, repoDir), "a build churned an added package")

	mustRemove(t, repoDir, confPath, "", "", "", "hello-world=2.0")
	afterRemove := snapshotTree(t, repoDir)

	mustBuild(t, repoDir, confPath, false, false)
	require.Equal(t, afterRemove, snapshotTree(t, repoDir), "a build churned a removed package")

	verifyRepo(t, repoDir, testReleaseName)

	assert.Equal(t, []string{"hello-world 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))
}

// TestAddedPackageReturnsWhenTheConfigStillMatchesIt pins the documented
// caveat: a removal withdraws a publication, it does not edit the
// configuration, so a .deb the globs still match comes back on the next build.
func TestAddedPackageReturnsWhenTheConfigStillMatchesIt(t *testing.T) {
	repoDir := t.TempDir()

	confPath := writeTestConfig(t, singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb")))

	mustBuild(t, repoDir, confPath, false, false)

	mustRemove(t, repoDir, confPath, "", "", "", "hello-world=2.0")
	require.Equal(t, []string{"hello-world 1.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	mustBuild(t, repoDir, confPath, false, false)

	assert.Equal(t, []string{"hello-world 1.0 amd64", "hello-world 2.0 amd64"},
		packageVersions(packagesIn(t, repoDir, "amd64")))

	verifyRepo(t, repoDir, testReleaseName)
}
