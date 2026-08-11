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

package keys

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The generated key has to carry the identity the CLI was given and be usable
// for signing, which is the only thing the repository ever asks of it.
func TestGenerateIdentity(t *testing.T) {
	entity, err := generate("Test User", "test comment", "test@example.com", 1024)
	require.NoError(t, err)

	require.Len(t, entity.Identities, 1)

	for _, identity := range entity.Identities {
		assert.Equal(t, "Test User", identity.UserId.Name)
		assert.Equal(t, "test comment", identity.UserId.Comment)
		assert.Equal(t, "test@example.com", identity.UserId.Email)
	}

	require.NotNil(t, entity.PrivateKey)
	assert.False(t, entity.PrivateKey.Encrypted)

	_, ok := entity.SigningKey(time.Now())
	assert.True(t, ok)
}

// The private key must never be written world readable, and it has to survive
// the armor round trip so that a later build signs with the same key.
func TestWritePrivateAndLoad(t *testing.T) {
	entity, err := generate("Test User", "", "test@example.com", 1024)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "aptify_private.asc")
	require.NoError(t, WritePrivate(path, entity))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	loaded, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, entity.PrimaryKey.Fingerprint, loaded.PrimaryKey.Fingerprint)
	assert.NotNil(t, loaded.PrivateKey)
}

// A missing or malformed key file has to be reported, not silently accepted.
func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()

	_, err := Load(filepath.Join(dir, "missing.asc"))
	assert.Error(t, err)

	notAKey := filepath.Join(dir, "not-a-key.asc")
	require.NoError(t, os.WriteFile(notAKey, []byte("this is not a key\n"), 0o600))

	_, err = Load(notAKey)
	assert.Error(t, err)
}
