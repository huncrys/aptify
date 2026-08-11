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

package repofs

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsS3URL pins which repository targets name a bucket. Everything else is
// a path, including one that merely mentions s3.
func TestIsS3URL(t *testing.T) {
	for target, want := range map[string]bool{
		"s3://bucket":            true,
		"s3://bucket/apt/debian": true,
		"repository":             false,
		"/srv/repository":        false,
		"./s3://bucket":          false,
		"s3-backup":              false,
		"https://example.com":    false,
	} {
		assert.Equal(t, want, IsS3URL(target), target)
	}
}

// TestNewLocalTarget checks that anything that is not a URL is still a
// directory, which is what every existing invocation passes.
func TestNewLocalTarget(t *testing.T) {
	dir := t.TempDir()

	fsys, err := New(context.Background(), dir)
	require.NoError(t, err)

	assert.Equal(t, dir, fsys.Name())
}

// TestNewS3Target covers the URL: the host is the bucket and the path is the
// prefix the repository lives below, with or without its slashes.
func TestNewS3Target(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "eu-central-1")

	for target, want := range map[string]string{
		"s3://bucket":             "s3://bucket",
		"s3://bucket/":            "s3://bucket",
		"s3://bucket/apt":         "s3://bucket/apt",
		"s3://bucket/apt/debian/": "s3://bucket/apt/debian",
	} {
		fsys, err := New(context.Background(), target)
		require.NoError(t, err, target)

		assert.Equal(t, want, fsys.Name(), target)
	}
}

// TestNewRejectsABucketlessURL pins the error rather than a repository
// published into nowhere.
func TestNewRejectsABucketlessURL(t *testing.T) {
	_, err := New(context.Background(), "s3:///apt/debian")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "names no bucket")
}

// TestUsePathStyle covers how the bucket is addressed: a custom endpoint is
// taken to be a self-hosted implementation, which is reached by path, and the
// query parameter decides it either way.
func TestUsePathStyle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		target   string
		endpoint string
		want     bool
	}{
		{name: "amazon", target: "s3://bucket"},
		{name: "custom endpoint", target: "s3://bucket", endpoint: "https://s3.example.com", want: true},
		{name: "asked for", target: "s3://bucket?path_style=true", want: true},
		{
			name:     "declined despite a custom endpoint",
			target:   "s3://bucket?path_style=false",
			endpoint: "https://s3.example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_ENDPOINT_URL", tc.endpoint)

			u, err := url.Parse(tc.target)
			require.NoError(t, err)

			got, err := usePathStyle(u)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestUsePathStyleRejectsRubbish pins that an unreadable knob is an error
// rather than a silent default, since getting it wrong makes every request
// fail against a self-hosted bucket.
func TestUsePathStyleRejectsRubbish(t *testing.T) {
	u, err := url.Parse("s3://bucket?path_style=maybe")
	require.NoError(t, err)

	_, err = usePathStyle(u)
	assert.Error(t, err)
}
