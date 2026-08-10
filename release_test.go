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

package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	stdtime "time"

	"oaklab.hu/debian/aptify/internal/hashsum"
	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
)

// TestNoSupportForArchitectureAll covers the rule the field encodes:
// architecture `all` packages are folded into every architecture's indices,
// unless a component has nothing to fold them into and publishes binary-all of
// its own - and then the field would tell apt to ignore indices the release
// does list.
func TestNoSupportForArchitectureAll(t *testing.T) {
	for _, tc := range []struct {
		name          string
		architectures []string
		want          string
	}{
		// A release publishing no architecture `all` packages at all, and one
		// that folds them into every architecture, name the same
		// architectures: `all` is not one of them either way.
		{"multiple architectures", []string{"amd64", "arm64"}, "Packages"},
		{"single architecture", []string{"amd64"}, "Packages"},
		{"all published alongside an architecture", []string{"all", "amd64"}, ""},
		{"nothing to fold all into", []string{"all"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var architectures []arch.Arch
			for _, architecture := range tc.architectures {
				architectures = append(architectures, arch.MustParse(architecture))
			}

			if got := noSupportForArchitectureAll(architectures); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestByHashSets checks that the two views of a by-hash generation agree: what
// this build publishes is derived from the checksums, what the previous one
// published from the release file it wrote, and the prune compares them.
func TestByHashSets(t *testing.T) {
	sums := []hashsum.Sums{
		{Path: "main/binary-amd64/Packages", Size: 3, MD5: "md5", SHA1: "sha1", SHA256: "sha256"},
		{Path: "main/Contents-amd64.gz", Size: 3, MD5: "cmd5", SHA1: "csha1", SHA256: "csha256"},
	}

	want := map[string]map[string]bool{
		"main/binary-amd64/by-hash/MD5Sum": {"md5": true},
		"main/binary-amd64/by-hash/SHA1":   {"sha1": true},
		"main/binary-amd64/by-hash/SHA256": {"sha256": true},
		"main/by-hash/MD5Sum":              {"cmd5": true},
		"main/by-hash/SHA1":                {"csha1": true},
		"main/by-hash/SHA256":              {"csha256": true},
	}

	got := byHashSets(sums)
	if !maps.EqualFunc(got, want, maps.Equal) {
		t.Errorf("byHashSets:\n got %v\nwant %v", got, want)
	}

	release := &types.Release{
		MD5Sum: hashsum.MD5List(sums),
		SHA1:   hashsum.SHA1List(sums),
		SHA256: hashsum.SHA256List(sums),
	}

	fromRelease := byHashSetsFromRelease(release)
	if !maps.EqualFunc(fromRelease, want, maps.Equal) {
		t.Errorf("byHashSetsFromRelease:\n got %v\nwant %v", fromRelease, want)
	}
}

// TestPruneByHash walks the scenario a naive age sweep gets wrong: an indice
// that sat unchanged for a month, and then changed. Its predecessor's mtime is
// when its content was created, not when it stopped being current, so it has
// to be touched as it leaves the release and only expire a retention window
// after that.
func TestPruneByHash(t *testing.T) {
	const retention = 7 * 24 * stdtime.Hour

	releaseDir := t.TempDir()

	// The Contents indice lives at component level, so its by-hash tree does
	// too; both have to be swept.
	dirs := []string{"main/binary-amd64/by-hash/SHA256", "main/by-hash/SHA256"}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(releaseDir, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	entryPath := func(dir, name string) string {
		return filepath.Join(releaseDir, filepath.FromSlash(dir), name)
	}

	write := func(dir, name string, age stdtime.Duration) {
		t.Helper()

		path := entryPath(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stdtime.Time{}, stdtime.Now().Add(-age)); err != nil {
			t.Fatal(err)
		}
	}

	exists := func(dir, name string) bool {
		t.Helper()

		_, err := os.Stat(entryPath(dir, name))

		return err == nil
	}

	sets := func(names ...string) map[string]map[string]bool {
		set := make(map[string]map[string]bool)
		for _, dir := range dirs {
			set[dir] = make(map[string]bool)
			for _, name := range names {
				set[dir][name] = true
			}
		}

		return set
	}

	// The indice has held the same content for a month.
	for _, dir := range dirs {
		write(dir, "old", 30*24*stdtime.Hour)
	}

	if err := pruneByHash(releaseDir, sets("old"), sets("old"), retention); err != nil {
		t.Fatal(err)
	}

	for _, dir := range dirs {
		if !exists(dir, "old") {
			t.Fatalf("%s: the current entry was swept despite being current", dir)
		}
	}

	// Now it changes. The predecessor is a month old but has only just been
	// superseded, so it must survive and start its retention window here.
	for _, dir := range dirs {
		write(dir, "new", 0)
	}

	if err := pruneByHash(releaseDir, sets("new"), sets("old"), retention); err != nil {
		t.Fatal(err)
	}

	for _, dir := range dirs {
		if !exists(dir, "old") {
			t.Fatalf("%s: the superseded entry was deleted the moment it was superseded", dir)
		}

		fi, err := os.Stat(entryPath(dir, "old"))
		if err != nil {
			t.Fatal(err)
		}
		if stdtime.Since(fi.ModTime()) > stdtime.Minute {
			t.Errorf("%s: the superseded entry was not touched, its mtime is %s", dir, fi.ModTime())
		}
	}

	// A later build names neither: still inside the window.
	if err := pruneByHash(releaseDir, sets("new"), sets("new"), retention); err != nil {
		t.Fatal(err)
	}

	for _, dir := range dirs {
		if !exists(dir, "old") {
			t.Fatalf("%s: the superseded entry expired before the retention window was up", dir)
		}
	}

	// Once the window is up it goes, and only it.
	for _, dir := range dirs {
		write(dir, "old", retention+stdtime.Hour)
	}

	if err := pruneByHash(releaseDir, sets("new"), sets("new"), retention); err != nil {
		t.Fatal(err)
	}

	for _, dir := range dirs {
		if exists(dir, "old") {
			t.Errorf("%s: the expired entry was kept", dir)
		}
		if !exists(dir, "new") {
			t.Errorf("%s: the current entry was removed", dir)
		}
	}
}

// TestPruneByHashKeepsCurrentEntries checks that an entry the new release
// names is left alone however old its content is, since it is the content that
// is old, not the entry.
func TestPruneByHashKeepsCurrentEntries(t *testing.T) {
	releaseDir := t.TempDir()

	dir := filepath.Join(releaseDir, "main", "binary-amd64", "by-hash", "SHA256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "current")
	if err := os.WriteFile(path, []byte("current"), 0o644); err != nil {
		t.Fatal(err)
	}

	modTime := stdtime.Now().Add(-365 * 24 * stdtime.Hour).Truncate(stdtime.Second)
	if err := os.Chtimes(path, stdtime.Time{}, modTime); err != nil {
		t.Fatal(err)
	}

	current := map[string]map[string]bool{"main/binary-amd64/by-hash/SHA256": {"current": true}}

	if err := pruneByHash(releaseDir, current, current, stdtime.Hour); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the current entry was removed: %v", err)
	}
	if !fi.ModTime().Equal(modTime) {
		t.Errorf("the current entry was touched: got %s, want %s", fi.ModTime(), modTime)
	}
}

// TestRemoveByHash covers turning the feature off: every tree goes, and
// nothing else does.
func TestRemoveByHash(t *testing.T) {
	releaseDir := t.TempDir()

	for _, name := range []string{
		"main/binary-amd64/by-hash/SHA256/cafebabe",
		"main/by-hash/MD5Sum/deadbeef",
		"main/binary-amd64/Packages",
	} {
		path := filepath.Join(releaseDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeByHash(releaseDir); err != nil {
		t.Fatal(err)
	}

	var left []string
	if err := filepath.WalkDir(releaseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(releaseDir, path)
		if err != nil {
			return err
		}
		left = append(left, filepath.ToSlash(relativePath))

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(left, []string{"main/binary-amd64/Packages"}) {
		t.Errorf("remaining files: got %q, want [main/binary-amd64/Packages]", left)
	}
}
