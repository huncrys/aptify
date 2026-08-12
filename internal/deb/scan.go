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

package deb

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/dpeckett/archivefs/arfs"
	"github.com/dpeckett/uncompr"
)

// docDir is where a package ships its changelog, under its own name or under
// that of the source package it was built from.
const docDir = "usr/share/doc"

// Scan is everything one walk of a package's data archive collects: the file
// listing a Contents indice describes the package by, and what it takes to
// answer for the changelog without opening the archive a second time.
type Scan struct {
	// Contents are the non-directory paths the package ships, sorted.
	Contents []string

	// modTime is the modification time of the package itself, which is what
	// dates a changelog the caller has to synthesise.
	modTime time.Time

	// changelogs holds the changelog candidates still compressed, keyed by
	// their path in the archive. There are at most a handful and they are
	// kilobytes each, so buffering them costs less than a second walk.
	changelogs map[string]changelogCandidate

	// symlinks are the documentation paths shipped as symlinks, which is what
	// separates a package whose changelog the walker refuses to follow from one
	// shipping none at all.
	symlinks map[string]bool
}

type changelogCandidate struct {
	data    []byte
	modTime time.Time
}

// unreadableError reports a package file that could not be opened at all,
// which is not the same as it shipping nothing: each reader phrases it its own
// way, and the cause stays visible to errors.Is.
type unreadableError struct {
	err error
}

func (e *unreadableError) Error() string {
	return fmt.Sprintf("%s: %s", ErrPackageUnreadable, e.err)
}

func (e *unreadableError) Unwrap() []error {
	return []error{ErrPackageUnreadable, e.err}
}

// ScanPackage walks the data archive of the package named by fsys and name
// once, which is what every reader of a package's payload shares.
func ScanPackage(fsys fs.FS, name string) (*Scan, error) {
	f, err := openPackage(fsys, name)
	if err != nil {
		return nil, &unreadableError{err}
	}
	defer func() { _ = f.Close() }()

	debFS, err := arfs.Open(f)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}

	if err := ensureIsDebianPackage(debFS); err != nil {
		return nil, err
	}

	// Look for data archive in the debian package.
	entries, err := debFS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read debian package: %w", err)
	}

	var dataArchiveFilename string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "data.tar") {
			dataArchiveFilename = entry.Name()
			break
		}
	}
	if dataArchiveFilename == "" {
		return nil, fmt.Errorf("failed to find data archive in debian package")
	}

	dataArchiveFile, err := debFS.Open(dataArchiveFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open data archive: %w", err)
	}
	defer func() { _ = dataArchiveFile.Close() }()

	// Decompressed as a stream: the walk below needs no more than one pass, so
	// nothing is spilled and the memory a large package costs stays bounded.
	r, err := uncompr.NewReader(dataArchiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data archive: %w", err)
	}
	defer func() { _ = r.Close() }()

	scan := &Scan{
		modTime:    f.modTime,
		changelogs: make(map[string]changelogCandidate),
		symlinks:   make(map[string]bool),
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to read data archive: %w", err)
		}

		entry := strings.TrimPrefix(path.Clean(hdr.Name), "./")
		if entry == "." || entry == "" {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		case tar.TypeSymlink:
			// Recorded for files as well as directories: either shape of link
			// is a changelog the walker will not follow.
			if strings.HasPrefix(entry, docDir+"/") {
				scan.symlinks[entry] = true
			}
		case tar.TypeReg:
			if isChangelogCandidate(entry) {
				data, err := io.ReadAll(tr)
				if err != nil {
					return nil, fmt.Errorf("failed to read changelog file: %w", err)
				}

				scan.changelogs[entry] = changelogCandidate{data: data, modTime: hdr.ModTime}
			}
		}

		scan.Contents = append(scan.Contents, entry)
	}

	// A stream does not dedupe the way a filesystem view of the archive did.
	slices.Sort(scan.Contents)
	scan.Contents = slices.Compact(scan.Contents)

	return scan, nil
}

// Changelog reports the changelog of the binary package name built from source,
// which ships under either name. A package shipping none reports os.ErrNotExist
// and one whose documentation directory is a symlink ErrChangelogSymlink, both
// with the package's own modification time, so that the placeholder the caller
// writes is not dated by the build.
func (s *Scan) Changelog(source, name string) ([]byte, time.Time, error) {
	candidates := []string{
		path.Join(docDir, name, "changelog.Debian.gz"),
		path.Join(docDir, name, "changelog.gz"),
	}

	if source != name && source != "" {
		candidates = append(candidates,
			path.Join(docDir, source, "changelog.Debian.gz"),
			path.Join(docDir, source, "changelog.gz"))
	}

	for _, candidate := range candidates {
		buffered, ok := s.changelogs[candidate]
		if !ok {
			// A symlink short-circuits the remaining candidates, exactly as
			// refusing to follow it did: a package whose own documentation
			// directory is a link does not fall through to the source's.
			for _, link := range []string{path.Dir(candidate), candidate} {
				if s.symlinks[link] {
					return nil, s.modTime, ErrChangelogSymlink
				}
			}

			continue
		}

		changelogReader, err := uncompr.NewReader(bytes.NewReader(buffered.data))
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to decompress changelog file: %w", err)
		}

		changelogData, err := io.ReadAll(changelogReader)
		_ = changelogReader.Close()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to read changelog file: %w", err)
		}

		if len(changelogData) > 0 {
			return changelogData, buffered.modTime, nil
		}
	}

	return nil, s.modTime, os.ErrNotExist
}

// isChangelogCandidate reports whether a path is a changelog a package could be
// asked for, which is only ever one directory deep under usr/share/doc.
func isChangelogCandidate(name string) bool {
	switch path.Base(name) {
	case "changelog.Debian.gz", "changelog.gz":
		return path.Dir(path.Dir(name)) == docDir
	default:
		return false
	}
}
