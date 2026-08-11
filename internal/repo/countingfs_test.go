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
	"io"
	"io/fs"
	"strings"
	"testing"
	stdtime "time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// countingFS records what a build asks of its storage. Every operation a
// remote backend would pay a round trip for is counted, which is what makes
// "an unchanged rebuild publishes nothing" checkable as something other than a
// snapshot comparison.
type countingFS struct {
	repofs.FS

	writes  int
	clones  int
	removes int
	chtimes int
	// poolReads counts the pool files opened for reading, which is the one
	// read a remote backend pays for by the megabyte.
	poolReads int
}

func newCountingFS(root string) *countingFS {
	return &countingFS{FS: repofs.NewOS(root)}
}

func (c *countingFS) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "pool/") {
		c.poolReads++
	}

	return c.FS.Open(name)
}

func (c *countingFS) WriteFile(name string, body []byte, perm fs.FileMode, mtime stdtime.Time) error {
	c.writes++

	return c.FS.WriteFile(name, body, perm, mtime)
}

func (c *countingFS) WriteFrom(name string, r io.Reader, size int64, mtime stdtime.Time) error {
	c.writes++

	return c.FS.WriteFrom(name, r, size, mtime)
}

func (c *countingFS) Clone(oldname, newname string) error {
	c.clones++

	return c.FS.Clone(oldname, newname)
}

func (c *countingFS) Remove(name string) error {
	c.removes++

	return c.FS.Remove(name)
}

func (c *countingFS) RemoveAll(name string) error {
	c.removes++

	return c.FS.RemoveAll(name)
}

func (c *countingFS) Chtimes(name string, mtime stdtime.Time) error {
	c.chtimes++

	return c.FS.Chtimes(name, mtime)
}

// TestRebuildTouchesNothing pins the incrementality from the storage's side:
// rebuilding an unchanged repository issues no write, no clone, no delete and
// no touch at all. The snapshot comparisons elsewhere would not notice a
// rewrite that happened to produce the same bytes; a remote backend would pay
// for every one of them.
func TestRebuildTouchesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		byHash bool
	}{
		{name: "by-hash off"},
		{name: "by-hash on", byHash: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repoDir := t.TempDir()

			conf := singleComponentConfig(0,
				debPath(t, "hello-world_1.0_amd64.deb"),
				debPath(t, "hello-world_1.0_arm64.deb"),
				debPath(t, "hello-world_3.0_all.deb"))
			conf.URL = testRepositoryURL
			conf.Changelogs = true
			conf.ByHash.Enabled = tc.byHash

			confPath := writeTestConfig(t, conf)

			mustBuild(t, repoDir, confPath, false, false)
			verifyRepo(t, repoDir, testReleaseName)

			counting := newCountingFS(repoDir)

			require.NoError(t, Build(Options{
				FS:             counting,
				ConfigPath:     confPath,
				PrivateKeyPath: testKeyPath(t),
			}))

			assert.Zero(t, counting.writes, "an unchanged rebuild published something")
			assert.Zero(t, counting.clones, "an unchanged rebuild republished the by-hash tree")
			assert.Zero(t, counting.removes, "an unchanged rebuild deleted something")
			assert.Zero(t, counting.chtimes, "an unchanged rebuild touched something")
			assert.Zero(t, counting.poolReads, "an unchanged rebuild read the pool")
		})
	}
}
