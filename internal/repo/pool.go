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
	"fmt"
	"path"
	"strings"

	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
)

// archAll is the architecture whose packages belong in every architecture's
// indices rather than in one of its own.
var archAll = new(arch.MustParse("all"))

// sourceNameOf is the source package a binary package is filed under: the
// Source field when it names one, otherwise the binary package standing in for
// its own source. Control fields arrive with their surrounding whitespace still
// attached, so either name is trimmed before it becomes part of a path.
func sourceNameOf(pkg *types.Package) string {
	if pkg.Source != nil {
		if source := strings.TrimSpace(pkg.Source.Name); source != "" {
			return source
		}
	}

	return strings.TrimSpace(pkg.Name)
}

// sourcePrefix is the directory a source package is filed under: its first
// letter, or lib? so that the thousands of lib* sources do not land in one
// enormous l/. A name too short for the lib? form, "lib" itself included, keeps
// the plain first letter, and a package that names nothing at all gets no
// prefix rather than a panic.
func sourcePrefix(source string) string {
	switch {
	case source == "":
		return ""
	case len(source) > 3 && strings.HasPrefix(source, "lib"):
		return source[:4]
	default:
		return source[:1]
	}
}

func poolPathForPackage(componentName string, pkg *types.Package) string {
	source := sourceNameOf(pkg)

	// Debian names pool files without the epoch, so that the URL apt fetches
	// carries no colon.
	return path.Join("pool", componentName, sourcePrefix(source), source,
		fmt.Sprintf("%s_%s_%s.deb", strings.TrimSpace(pkg.Name),
			pkg.Version.StringWithoutEpoch(), pkg.Architecture))
}
