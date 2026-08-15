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

// Package keys handles the OpenPGP key a repository is signed with: generating
// a new one, storing the private half, loading it back, and exporting the
// public half clients verify the release against.
package keys

import (
	"bytes"
	"fmt"
	"io"
	"os"
	stdtime "time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Generate creates a new RSA signing key for the given identity.
func Generate(name, comment, email string) (*openpgp.Entity, error) {
	return generate(name, comment, email, 4096)
}

// generate creates a new RSA signing key of the given size; tests use a small
// key so that they do not spend seconds on entropy.
func generate(name, comment, email string, rsaBits int) (*openpgp.Entity, error) {
	entityConfig := &packet.Config{
		RSABits: rsaBits,
		Time:    stdtime.Now,
	}

	entity, err := openpgp.NewEntity(name, comment, email, entityConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create entity: %w", err)
	}

	return entity, nil
}

// WritePrivate writes the armored private key to path, readable only by its
// owner.
func WritePrivate(path string, entity *openpgp.Entity) error {
	var privateKey bytes.Buffer
	privateKeyWriter, err := armor.Encode(&privateKey, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}
	if err := entity.SerializePrivate(privateKeyWriter, nil); err != nil {
		return fmt.Errorf("failed to serialize private key: %w", err)
	}
	if err := privateKeyWriter.Close(); err != nil {
		return fmt.Errorf("failed to close private key writer: %w", err)
	}

	if err := os.WriteFile(path, privateKey.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// Load reads the armored private key stored at path.
func Load(path string) (*openpgp.Entity, error) {
	keyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key: %w", err)
	}
	defer func() { _ = keyFile.Close() }()

	keyRing, err := openpgp.ReadArmoredKeyRing(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read armored key ring: %w", err)
	}

	return keyRing[0], nil
}

// WritePublic writes the armored public half of the key, which is what a
// client imports to verify the repository.
func WritePublic(w io.Writer, entity *openpgp.Entity) error {
	publicKeyWriter, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	if err := entity.Serialize(publicKeyWriter); err != nil {
		return fmt.Errorf("failed to serialize public key: %w", err)
	}

	if err := publicKeyWriter.Close(); err != nil {
		return fmt.Errorf("failed to close public key writer: %w", err)
	}

	return nil
}
