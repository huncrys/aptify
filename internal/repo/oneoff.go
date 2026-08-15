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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"oaklab.hu/debian/aptify/internal/config/v1alpha1"
	"oaklab.hu/debian/aptify/internal/deb"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/version"
)

// AddOptions names the packages a one-off add publishes and where they go. The
// configuration is still required: the release metadata, by_hash, changelogs
// and max_versions all keep coming from it, and only a component the config
// names has its indices rewritten.
type AddOptions struct {
	Options

	// Release and Component are the target. Either may be empty when the
	// configuration leaves exactly one thing it could mean.
	Release, Component string
	// Packages are literal paths to local .deb files. Globs are the shell's
	// business, so every one of them has to exist.
	Packages []string
}

// RemoveOptions names the packages a one-off removal withdraws.
type RemoveOptions struct {
	Options

	// Release and Component are the target, defaulted the same way as for an
	// add.
	Release, Component string
	// Arch narrows every selector to one architecture's indices.
	Arch string
	// Selectors are package names, "name=version" pairs, or paths to local
	// .deb files standing for exactly the package they hold.
	Selectors []string
}

// Add publishes local .deb files into a component of an already built
// repository, then runs the rest of the pipeline exactly as a build does: the
// pruning, the indices, the pool collection, the changelogs and the signature
// all read the same package lists whichever way they were filled.
func Add(opts AddOptions) error {
	if len(opts.Packages) == 0 {
		return errors.New("no packages given")
	}

	b, err := newBuild(opts.Options)
	if err != nil {
		return err
	}

	releaseName, componentName, err := b.resolveTarget(opts.Release, opts.Component)
	if err != nil {
		return err
	}

	// Every path is checked before anything is published, so a typo in the last
	// argument does not leave the first one half added.
	for _, pkgPath := range opts.Packages {
		fi, err := os.Stat(pkgPath)
		if err != nil {
			return fmt.Errorf("failed to read package %s: %w", pkgPath, err)
		}
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory, not a package", pkgPath)
		}
	}

	releaseComponent := fmt.Sprintf("%s/%s", releaseName, componentName)

	return b.run(func() error {
		for _, pkgPath := range opts.Packages {
			slog.Info("Adding package",
				slog.String("file", pkgPath),
				slog.String("release", releaseName),
				slog.String("component", componentName))

			if err := b.ingestPackage(releaseComponent, componentName, pkgPath); err != nil {
				return err
			}
		}

		return nil
	})
}

// Remove withdraws packages from a component of an already built repository.
// The stanzas move from the published list into the removed one, keeping the
// Filename they were published with, which is what the Contents rewrite and the
// pool collection go on.
func Remove(opts RemoveOptions) error {
	if len(opts.Selectors) == 0 {
		return errors.New("no packages given")
	}

	b, err := newBuild(opts.Options)
	if err != nil {
		return err
	}

	releaseName, componentName, err := b.resolveTarget(opts.Release, opts.Component)
	if err != nil {
		return err
	}

	selectors, err := parseSelectors(opts.Selectors)
	if err != nil {
		return err
	}

	releaseComponent := fmt.Sprintf("%s/%s", releaseName, componentName)

	return b.run(func() error {
		return b.removePackages(releaseComponent, selectors, opts.Arch)
	})
}

// resolveTarget picks the release and component a one-off operation applies to.
// Both have to be named by the configuration: writeIndices iterates the
// configured releases, so a component the config does not carry would keep its
// package lists and never have them published. Either may be left out when
// there is only one thing it could mean.
func (b *build) resolveTarget(release, component string) (string, string, error) {
	var releaseConf *v1alpha1.ReleaseConfig

	switch {
	case release != "":
		for i := range b.conf.Releases {
			if b.conf.Releases[i].Name == release {
				releaseConf = &b.conf.Releases[i]
				break
			}
		}

		if releaseConf == nil {
			return "", "", fmt.Errorf("the configuration has no release %q (it has: %s)",
				release, strings.Join(releaseNames(b.conf.Releases), ", "))
		}
	case len(b.conf.Releases) == 1:
		releaseConf = &b.conf.Releases[0]
	case len(b.conf.Releases) == 0:
		return "", "", errors.New("the configuration has no releases")
	default:
		return "", "", fmt.Errorf("the configuration has more than one release, name one (it has: %s)",
			strings.Join(releaseNames(b.conf.Releases), ", "))
	}

	var componentConf *v1alpha1.ComponentConfig

	switch {
	case component != "":
		for i := range releaseConf.Components {
			if releaseConf.Components[i].Name == component {
				componentConf = &releaseConf.Components[i]
				break
			}
		}

		if componentConf == nil {
			return "", "", fmt.Errorf("release %s has no component %q (it has: %s)",
				releaseConf.Name, component, strings.Join(componentNames(releaseConf.Components), ", "))
		}
	case len(releaseConf.Components) == 1:
		componentConf = &releaseConf.Components[0]
	case len(releaseConf.Components) == 0:
		return "", "", fmt.Errorf("release %s has no components", releaseConf.Name)
	default:
		return "", "", fmt.Errorf("release %s has more than one component, name one (it has: %s)",
			releaseConf.Name, strings.Join(componentNames(releaseConf.Components), ", "))
	}

	return releaseConf.Name, componentConf.Name, nil
}

// releaseNames is what an error message lists as the releases on offer.
func releaseNames(releases []v1alpha1.ReleaseConfig) []string {
	names := make([]string, 0, len(releases))
	for _, releaseConf := range releases {
		names = append(names, releaseConf.Name)
	}

	return names
}

// componentNames is the same list for the components of one release.
func componentNames(components []v1alpha1.ComponentConfig) []string {
	names := make([]string, 0, len(components))
	for _, componentConf := range components {
		names = append(names, componentConf.Name)
	}

	return names
}

// selector is one argument of a removal, resolved to what it matches: a package
// name, optionally a version, and optionally an architecture when the argument
// was a .deb file standing for exactly the package it holds.
type selector struct {
	// raw is the argument as it was written, which is what an error names.
	raw string
	// name is the package name every selector matches by.
	name string
	// version is nil when the selector matches every published version.
	version *version.Version
	// architecture is empty unless the selector pins one.
	architecture string
}

// matches reports whether a published stanza is one this selector names.
func (s selector) matches(pkg types.Package) bool {
	if strings.TrimSpace(pkg.Name) != s.name {
		return false
	}

	if s.version != nil && pkg.Version.Compare(*s.version) != 0 {
		return false
	}

	if s.architecture != "" && pkg.Architecture.String() != s.architecture {
		return false
	}

	return true
}

// parseSelectors resolves every argument of a removal, reporting all of the
// unusable ones at once rather than stopping at the first.
func parseSelectors(args []string) ([]selector, error) {
	selectors := make([]selector, 0, len(args))

	var problems []error
	for _, arg := range args {
		sel, err := parseSelector(arg)
		if err != nil {
			problems = append(problems, err)
			continue
		}

		selectors = append(selectors, sel)
	}

	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}

	return selectors, nil
}

// parseSelector reads one removal argument. A path to an existing file, and
// anything named like a .deb, is the package that file holds - read rather than
// guessed at, so the name, version and architecture are exactly the published
// ones. Everything else is a name, optionally pinned to a version after an "="
// - a character neither a package name nor a version may contain.
func parseSelector(arg string) (selector, error) {
	if strings.HasSuffix(arg, ".deb") || isExistingFile(arg) {
		pkg, err := deb.GetMetadata(repofs.LocalFile(arg))
		if err != nil {
			return selector{}, fmt.Errorf("failed to read package %s: %w", arg, err)
		}

		return selector{
			raw:          arg,
			name:         strings.TrimSpace(pkg.Name),
			version:      &pkg.Version,
			architecture: pkg.Architecture.String(),
		}, nil
	}

	name, versionString, pinned := strings.Cut(arg, "=")
	if name == "" {
		return selector{}, fmt.Errorf("%q names no package", arg)
	}

	if !pinned {
		return selector{raw: arg, name: name}, nil
	}

	pinnedVersion, err := version.Parse(versionString)
	if err != nil {
		return selector{}, fmt.Errorf("%q does not name a version: %w", arg, err)
	}

	return selector{raw: arg, name: name, version: &pinnedVersion}, nil
}

// isExistingFile reports whether a selector addresses a local file rather than
// naming a package.
func isExistingFile(arg string) bool {
	fi, err := os.Stat(filepath.FromSlash(arg))

	return err == nil && !fi.IsDir()
}

// removePackages moves everything the selectors name out of a component's
// published list and into its removed one. A selector that names nothing is an
// error - a typo must not be reported as a successful removal - and so is one
// narrowed by an architecture it cannot be narrowed to; both are collected so
// that a single run lists every one of them.
func (b *build) removePackages(releaseComponent string, selectors []selector, architecture string) error {
	published := b.packages[releaseComponent]

	var (
		problems []error
		matched  []types.Package
	)

	for _, sel := range selectors {
		found, err := sel.selectFrom(published, architecture)
		if err != nil {
			problems = append(problems, err)
			continue
		}

		if len(found) == 0 {
			problems = append(problems, fmt.Errorf("%s matches no package published by %s",
				sel.raw, releaseComponent))
			continue
		}

		matched = append(matched, found...)
	}

	if len(problems) > 0 {
		return errors.Join(problems...)
	}

	for _, pkg := range matched {
		comparator := func(existingPkg types.Package) bool {
			return existingPkg.Compare(pkg) == 0
		}

		// Overlapping selectors name the same stanza more than once; it is
		// removed the first time and skipped afterwards.
		if !slices.ContainsFunc(b.packages[releaseComponent], comparator) {
			continue
		}

		slog.Info("Removing package",
			slog.String("name", pkg.Name),
			slog.String("version", pkg.Version.String()),
			slog.String("architecture", pkg.Architecture.String()),
			slog.String("filename", pkg.Filename))

		b.packages[releaseComponent] = slices.DeleteFunc(b.packages[releaseComponent], comparator)
		b.removed[releaseComponent] = append(b.removed[releaseComponent], pkg)
	}

	return nil
}

// selectFrom narrows a component's published packages to the ones a selector
// names. An architecture filter selects what that architecture's indices
// publish, which folds the architecture `all` packages in: there is a single
// entry for one of those, shared by every architecture, so removing it for one
// architecture alone is not something the repository can express.
func (s selector) selectFrom(published []types.Package, architecture string) ([]types.Package, error) {
	var matched []types.Package

	for _, pkg := range published {
		if !s.matches(pkg) {
			continue
		}

		switch {
		case architecture == "" || pkg.Architecture.String() == architecture:
		case pkg.Architecture.Is(archAll):
			return nil, fmt.Errorf("%s matches %s, which is architecture all: it is published "+
				"in every architecture's indices, so it cannot be removed from %s alone",
				s.raw, pkg.ID(), architecture)
		default:
			continue
		}

		matched = append(matched, pkg)
	}

	return matched, nil
}
