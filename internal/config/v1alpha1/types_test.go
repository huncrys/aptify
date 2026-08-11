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

package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oaklab.hu/debian/aptify/internal/config/types"
)

// TestHasChangelogs pins that changelogs need both halves: the flag says to
// generate them, and the URL is what the Changelogs field of the release points
// at, so asking for them without a URL publishes nothing.
func TestHasChangelogs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		url        string
		changelogs bool
		want       bool
	}{
		{name: "neither", want: false},
		{name: "url only", url: "https://apt.example.com", want: false},
		{name: "flag only", changelogs: true, want: false},
		{name: "both", url: "https://apt.example.com", changelogs: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := Repository{URL: tc.url, Changelogs: tc.changelogs}

			assert.Equal(t, tc.want, conf.HasChangelogs())
		})
	}
}

// TestByHashEnabled pins that by-hash is off unless the config says so.
func TestByHashEnabled(t *testing.T) {
	assert.False(t, (&Repository{}).ByHashEnabled(), "by-hash is opt-in")
	assert.True(t, (&Repository{ByHash: ByHashConfig{Enabled: true}}).ByHashEnabled())
	assert.False(t, (&Repository{ByHash: ByHashConfig{Retention: time.Hour}}).ByHashEnabled(),
		"a retention alone does not turn the feature on")
}

// TestByHashRetention pins the seven day default and that anything which is not
// a positive duration - unset, zero, negative - falls back to it rather than
// expiring entries immediately.
func TestByHashRetention(t *testing.T) {
	const sevenDays = 7 * 24 * time.Hour

	for _, tc := range []struct {
		name      string
		retention time.Duration
		want      time.Duration
	}{
		{name: "unset", want: sevenDays},
		{name: "zero", retention: 0, want: sevenDays},
		{name: "negative", retention: -time.Hour, want: sevenDays},
		{name: "explicit", retention: 30 * time.Minute, want: 30 * time.Minute},
		{name: "explicit seven days", retention: sevenDays, want: sevenDays},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := Repository{ByHash: ByHashConfig{Retention: tc.retention}}

			assert.Equal(t, tc.want, conf.ByHashRetention())
		})
	}
}

// TestGetConfigByKind pins that Repository is the only kind this api version
// serves, and that it hands back an empty value ready to be unmarshalled into.
func TestGetConfigByKind(t *testing.T) {
	conf, err := GetConfigByKind("Repository")
	require.NoError(t, err)
	require.IsType(t, &Repository{}, conf)
	assert.Equal(t, &Repository{}, conf)

	for _, kind := range []string{"", "Mirror", "repository"} {
		conf, err := GetConfigByKind(kind)
		require.Error(t, err, "kind %q", kind)
		assert.Nil(t, conf)
		assert.Contains(t, err.Error(), "unsupported kind: "+kind)
	}
}

// TestPopulateTypeMeta pins that stamping the type meta is unconditional: it
// fills an empty value in and overwrites one that disagrees, which is what
// makes ToYAML output self describing.
func TestPopulateTypeMeta(t *testing.T) {
	conf := Repository{}
	conf.PopulateTypeMeta()
	assert.Equal(t, types.TypeMeta{APIVersion: APIVersion, Kind: "Repository"}, conf.TypeMeta)

	stale := Repository{TypeMeta: types.TypeMeta{APIVersion: "aptify/v0", Kind: "Mirror"}}
	stale.PopulateTypeMeta()
	assert.Equal(t, types.TypeMeta{APIVersion: APIVersion, Kind: "Repository"}, stale.TypeMeta)
}

// TestRepositoryImplementsConfig pins the reported api version and kind, and
// that a Repository is usable wherever the version dispatch expects a Config.
func TestRepositoryImplementsConfig(t *testing.T) {
	var conf types.Config = &Repository{}

	assert.Equal(t, "aptify/v1alpha1", APIVersion)
	assert.Equal(t, APIVersion, conf.GetAPIVersion())
	assert.Equal(t, "Repository", conf.GetKind())
}
