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
	"bytes"
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/repofs"
)

// errStatFS answers the stat of the repository root with a fixed error, which
// is what the wrong credentials, the wrong region or a network that is down
// look like to a build.
type errStatFS struct {
	repofs.FS

	err error
}

func (f errStatFS) Stat(name string) (fs.FileInfo, error) {
	if name == "." {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: f.err}
	}

	return f.FS.Stat(name)
}

// TestBuildFailsWhenExistingStateCannotBeRead pins the difference between a
// repository that is not there and one that cannot be read. A target that
// refuses reads but accepts writes would otherwise be republished from the
// configuration alone, dropping every package the configuration no longer
// lists.
func TestBuildFailsWhenExistingStateCannotBeRead(t *testing.T) {
	repoDir := t.TempDir()

	both := singleComponentConfig(0,
		debPath(t, "hello-world_1.0_amd64.deb"),
		debPath(t, "hello-world_2.0_amd64.deb"))

	mustBuild(t, repoDir, writeTestConfig(t, both), false, false)

	published := packageVersions(packagesIn(t, repoDir, "amd64"))
	require.Len(t, published, 2)

	// The configuration now lists one of the two, so a build that read the
	// repository as empty would publish exactly that one.
	fewer := singleComponentConfig(0, debPath(t, "hello-world_2.0_amd64.deb"))

	unreadable := errStatFS{FS: repofs.NewOS(repoDir), err: errors.New("access denied")}

	err := Build(Options{
		FS:             unreadable,
		ConfigPath:     writeTestConfig(t, fewer),
		PrivateKeyPath: testKeyPath(t),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")

	assert.Equal(t, published, packageVersions(packagesIn(t, repoDir, "amd64")),
		"a build that could not read the repository republished it")
}

// TestBuildTreatsMissingRepositoryAsFresh is the other half: a repository that
// is genuinely not there is what every first build starts from.
func TestBuildTreatsMissingRepositoryAsFresh(t *testing.T) {
	repoDir := t.TempDir()

	conf := singleComponentConfig(0, debPath(t, "hello-world_1.0_amd64.deb"))

	require.NoError(t, Build(Options{
		FS:             errStatFS{FS: repofs.NewOS(repoDir), err: fs.ErrNotExist},
		ConfigPath:     writeTestConfig(t, conf),
		PrivateKeyPath: testKeyPath(t),
	}))

	verifyRepo(t, repoDir, testReleaseName)
}

// TestInspectReportsUnderlyingErrors covers the same distinction from the read
// only side: "the repository does not exist" is a claim inspect may only make
// when that is what the storage said.
func TestInspectReportsUnderlyingErrors(t *testing.T) {
	repoDir := t.TempDir()

	mustBuild(t, repoDir, writeTestConfig(t,
		singleComponentConfig(0, debPath(t, "hello-world_1.0_amd64.deb"))), false, false)

	var out bytes.Buffer

	err := Inspect(errStatFS{FS: repofs.NewOS(repoDir), err: errors.New("access denied")}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")

	out.Reset()

	err = Inspect(errStatFS{FS: repofs.NewOS(repoDir), err: fs.ErrNotExist}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}
