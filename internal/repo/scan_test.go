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
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/deb"
)

// TestScanPoolCachesAcrossCalls pins what the cache buys: the Contents indice
// of every architecture and the changelogs all ask about the same .deb, and the
// build decompresses it once for all of them.
func TestScanPoolCachesAcrossCalls(t *testing.T) {
	repoDir := t.TempDir()
	poolPath := publishTestPackage(t, repoDir, "hello-world_1.0_amd64.deb")

	counting := newCountingFS(repoDir)
	b := &build{
		fsys:        counting,
		sourcePaths: make(map[string]string),
		scans:       make(map[string]*deb.Scan),
	}

	first, err := b.scanPool(poolPath)
	require.NoError(t, err)
	require.Equal(t, 1, counting.poolReads)
	require.NotEmpty(t, first.Contents)

	second, err := b.scanPool(poolPath)
	require.NoError(t, err)

	assert.Same(t, first, second)
	assert.Equal(t, 1, counting.poolReads, "the package was read a second time")
}

// TestScanPoolDoesNotCacheFailures pins that an unreadable package is reported
// as often as it is asked about: the changelogs warn per package, and a
// remembered failure would silence all but the first.
func TestScanPoolDoesNotCacheFailures(t *testing.T) {
	counting := newCountingFS(t.TempDir())
	b := &build{
		fsys:        counting,
		sourcePaths: make(map[string]string),
		scans:       make(map[string]*deb.Scan),
	}

	const poolPath = "pool/main/h/hello-world/no-such-package_9.9_amd64.deb"

	for range 2 {
		_, err := b.scanPool(poolPath)
		require.ErrorIs(t, err, deb.ErrPackageUnreadable)
	}

	assert.Equal(t, 2, counting.poolReads)
}

// publishTestPackage copies a checked in package into the repository's pool,
// which is what a build reads back when it did not ingest the file itself.
func publishTestPackage(t *testing.T, repoDir, name string) string {
	t.Helper()

	poolPath := path.Join("pool", "main", "h", "hello-world", name)

	body, err := os.ReadFile(debPath(t, name))
	require.NoError(t, err)

	localPath := filepath.Join(repoDir, filepath.FromSlash(poolPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(localPath), 0o755))
	require.NoError(t, os.WriteFile(localPath, body, 0o644))

	return poolPath
}
