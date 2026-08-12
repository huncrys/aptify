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

package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"path"
	"slices"
	"sort"

	"github.com/dpeckett/uncompr"
	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/deb822/contents"
	"oaklab.hu/debian/deb822/types"
)

// latestPackages picks the newest version of each package name.
func latestPackages(packages []types.Package) map[string]types.Package {
	latest := make(map[string]types.Package, len(packages))
	for _, pkg := range packages {
		if existing, ok := latest[pkg.Name]; ok && existing.Compare(pkg) >= 0 {
			continue
		}

		latest[pkg.Name] = pkg
	}

	return latest
}

// contentsIndiceComplete reports whether every published variant of the
// Contents indice for an architecture is already on disk.
func contentsIndiceComplete(fsys repofs.FS, componentDir, arch string) bool {
	for _, name := range contentsIndiceNames(arch) {
		if _, err := fsys.Stat(path.Join(componentDir, name)); err != nil {
			return false
		}
	}

	return true
}

// contentsIndiceNames returns the file names the Contents indice for an
// architecture is published under. apt resolves the indice by its uncompressed
// name in the Release file and only then picks a compressed variant to fetch,
// so an indice listed as Contents-<arch>.gz alone is never acquired.
func contentsIndiceNames(arch string) []string {
	return []string{
		fmt.Sprintf("Contents-%s", arch),
		fmt.Sprintf("Contents-%s.gz", arch),
	}
}

// writeContentsIndice rewrites the Contents indice for an architecture,
// reporting the checksums of every published variant and whether any of them
// changed. packages is everything the architecture publishes, newPackages and
// removedPackages what this build added and dropped; --reread forces every
// package to be read back from the pool rather than only those whose published
// contents can have changed.
func (b *build) writeContentsIndice(componentDir, arch string, packages, newPackages, removedPackages []types.Package) ([]hashsum.Sums, bool, error) {
	contentsPath := path.Join(componentDir, fmt.Sprintf("Contents-%s.gz", arch))

	// Paths shipped by each qualified package name, seeded with whatever the
	// existing indice holds for the packages we are not rewriting.
	packageFiles, err := readContentsIndice(b.fsys, contentsPath)
	if err != nil {
		return nil, false, err
	}

	// Contents has no version column, so a name can be described only once.
	// Describe the version a client would install: the newest one published
	// for this architecture, architecture `all` packages included.
	published := latestPackages(packages)

	// Drop whatever the indice still holds for names the architecture no
	// longer publishes at all.
	maps.DeleteFunc(packageFiles, func(qualifiedName string, _ []string) bool {
		_, ok := published[contents.ParseQualifiedName(qualifiedName).Name]
		return !ok
	})

	described := make(map[string]bool, len(packageFiles))
	for qualifiedName := range packageFiles {
		described[contents.ParseQualifiedName(qualifiedName).Name] = true
	}

	latestNew := latestPackages(newPackages)
	latestRemoved := latestPackages(removedPackages)

	slog.Info("Collecting package contents", slog.String("dir", componentDir))

	for _, name := range slices.Sorted(maps.Keys(published)) {
		pkg := published[name]

		// The indice describes whichever version was newest last time, so it
		// only goes stale when this build published a newer version or
		// removed the very one it described.
		stale := b.reread || !described[name]
		if added, ok := latestNew[name]; ok && added.Compare(pkg) == 0 {
			stale = true
		}
		if dropped, ok := latestRemoved[name]; ok && dropped.Compare(pkg) > 0 {
			stale = true
		}

		if !stale {
			continue
		}

		scan, err := b.scanPool(pkg.Filename)
		if err != nil {
			return nil, false, fmt.Errorf("failed to get package contents: %w %s", err, pkg.Filename)
		}

		// Drop the package's previous entries, whatever section it was filed
		// under back then.
		maps.DeleteFunc(packageFiles, func(qualifiedName string, _ []string) bool {
			return contents.ParseQualifiedName(qualifiedName).Name == name
		})

		qualifiedPackageName := pkg.Name
		if pkg.Section != "" {
			qualifiedPackageName = fmt.Sprintf("%s/%s", pkg.Section, pkg.Name)
		}

		packageFiles[qualifiedPackageName] = scan.Contents
	}

	// Invert into the layout of the file itself: one line per path, naming
	// every package that ships it.
	pathPackages := make(map[string][]string)
	for pkg, filePaths := range packageFiles {
		for _, filePath := range filePaths {
			if !slices.Contains(pathPackages[filePath], pkg) {
				pathPackages[filePath] = append(pathPackages[filePath], pkg)
			}
		}
	}

	filePaths := slices.Sorted(maps.Keys(pathPackages))

	slog.Info("Writing Contents indice",
		slog.String("dir", componentDir), slog.Int("count", len(filePaths)))

	var contentsList bytes.Buffer

	cw := contents.NewWriter(&contentsList)
	for _, filePath := range filePaths {
		packages := pathPackages[filePath]
		sort.Strings(packages)

		if err := cw.Write(contents.Entry{Path: filePath, Packages: packages}); err != nil {
			return nil, false, fmt.Errorf("failed to write contents: %w", err)
		}
	}

	var (
		sums    []hashsum.Sums
		changed bool
	)

	for _, name := range contentsIndiceNames(arch) {
		fileSums, fileChanged, err := writeIndiceFile(b.fsys, path.Join(componentDir, name), contentsList.Bytes())
		if err != nil {
			return sums, changed, fmt.Errorf("failed to write Contents file: %w", err)
		}

		sums = append(sums, fileSums)
		changed = changed || fileChanged
	}

	return sums, changed, nil
}

// readContentsIndice reads an existing Contents indice into the set of paths
// shipped by each qualified package name. A missing indice is not an error.
func readContentsIndice(fsys fs.FS, contentsPath string) (map[string][]string, error) {
	packageFiles := make(map[string][]string)

	f, err := fsys.Open(contentsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return packageFiles, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to open Contents file: %w", err)
	}
	defer f.Close()

	r, err := uncompr.NewReader(f)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// A previous run left an empty file behind.
			return packageFiles, nil
		}

		return nil, fmt.Errorf("failed to create decompression reader: %w", err)
	}
	defer r.Close()

	cr := contents.NewReader(r)
	for {
		entry, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read Contents file: %w", err)
		}

		for _, pkg := range entry.Packages {
			if !slices.Contains(packageFiles[pkg], entry.Path) {
				packageFiles[pkg] = append(packageFiles[pkg], entry.Path)
			}
		}
	}

	return packageFiles, nil
}
