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
	"fmt"
	"testing"
	stdtime "time"

	"oaklab.hu/debian/deb822/types/version"
)

// TestPlaceholderChangelog pins the placeholder against the format string it
// replaced, so that published changelogs do not change shape. The date is built
// in a named location because that is what a package file's mtime carries, and
// a zone name is invalid in a changelog trailer.
func TestPlaceholderChangelog(t *testing.T) {
	loc, err := stdtime.LoadLocation("Europe/Budapest")
	if err != nil {
		t.Fatal(err)
	}

	const (
		source     = "composer-phar"
		maintainer = "Kristof Bach <crys@crys.hu>"
	)

	pkgVer := version.MustParse("2.9.8")
	date := stdtime.Date(2026, stdtime.May, 13, 18, 4, 5, 0, loc)

	got, err := placeholderChangelog(source, pkgVer, maintainer, date)
	if err != nil {
		t.Fatal(err)
	}

	want := fmt.Sprintf("%s (%s) unstable; urgency=medium\n\n  * No changelog available.\n\n -- %s  %s\n",
		source, &pkgVer, maintainer, date.Format(stdtime.RFC1123Z))

	if string(got) != want {
		t.Errorf("placeholder changelog:\n got %q\nwant %q", got, want)
	}
}

// TestPlaceholderChangelogRejectsEmptyMaintainer covers the one input the old
// format string would have accepted: a package with no Maintainer field wrote a
// trailer that could not be parsed back.
func TestPlaceholderChangelogRejectsEmptyMaintainer(t *testing.T) {
	if _, err := placeholderChangelog("composer-phar", version.MustParse("2.9.8"), "", stdtime.Now()); err == nil {
		t.Error("expected an error for an empty maintainer")
	}
}
