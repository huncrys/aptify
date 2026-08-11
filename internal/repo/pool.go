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
	"path/filepath"
	"strings"

	"oaklab.hu/debian/deb822/types"
	"oaklab.hu/debian/deb822/types/arch"
)

// archAll is the architecture whose packages belong in every architecture's
// indices rather than in one of its own.
var archAll = new(arch.MustParse("all"))

func poolPathForPackage(componentName string, pkg *types.Package) string {
	pkgName := strings.TrimSpace(pkg.Name)
	var source string
	if pkg.Source != nil && pkg.Source.Name != "" {
		source = pkg.Source.Name
	} else {
		source = pkgName
	}

	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		prefix = source[:4]
	}

	return filepath.Join("pool", componentName, prefix, source,
		fmt.Sprintf("%s_%s_%s.deb", pkgName, pkg.Version, pkg.Architecture))
}
