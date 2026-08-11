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

package repofs_test

import (
	"testing"

	"oaklab.hu/debian/aptify/internal/repofs"
	"oaklab.hu/debian/aptify/internal/repofs/s3test"
)

// newTestS3 is a repository published to the root of a fresh fake bucket.
func newTestS3(t *testing.T) repofs.FS {
	t.Helper()

	return s3test.FS(t)
}

// newTestBackend is the same bucket, for the tests that address it by more
// than one prefix.
func newTestBackend(t *testing.T) testBackend {
	t.Helper()

	bucket := s3test.New(t)

	return testBackend{client: bucket.Client, bucket: bucket.Name}
}

type testBackend struct {
	client repofs.S3API
	bucket string
}
