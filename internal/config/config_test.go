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

package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	configtypes "oaklab.hu/debian/aptify/internal/config/types"
	latestconfig "oaklab.hu/debian/aptify/internal/config/v1alpha1"
)

// TestByHashConfig covers the block being opt-in: a config that says nothing
// about by-hash publishes exactly what it did before, and a retention is read
// as a duration rather than as a bare number of anything.
func TestByHashConfig(t *testing.T) {
	const header = "apiVersion: aptify/v1alpha1\nkind: Repository\nurl: https://apt.example.com\n"

	for _, tc := range []struct {
		name          string
		conf          string
		wantEnabled   bool
		wantRetention time.Duration
	}{
		{
			name:          "absent",
			conf:          header,
			wantEnabled:   false,
			wantRetention: 7 * 24 * time.Hour,
		},
		{
			name:          "enabled without a retention",
			conf:          header + "by_hash:\n  enabled: true\n",
			wantEnabled:   true,
			wantRetention: 7 * 24 * time.Hour,
		},
		{
			name:          "enabled with a retention",
			conf:          header + "by_hash:\n  enabled: true\n  retention: 168h\n",
			wantEnabled:   true,
			wantRetention: 168 * time.Hour,
		},
		{
			name:          "disabled with a retention",
			conf:          header + "by_hash:\n  enabled: false\n  retention: 30m\n",
			wantEnabled:   false,
			wantRetention: 30 * time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := FromYAML(strings.NewReader(tc.conf))
			if err != nil {
				t.Fatal(err)
			}

			if got := conf.ByHashEnabled(); got != tc.wantEnabled {
				t.Errorf("ByHashEnabled: got %t, want %t", got, tc.wantEnabled)
			}

			if got := conf.ByHashRetention(); got != tc.wantRetention {
				t.Errorf("ByHashRetention: got %s, want %s", got, tc.wantRetention)
			}
		})
	}
}

// demoConfig is shaped like examples/demo.yaml: the whole schema a user writes,
// including the snake_case keys that carry an explicit yaml tag.
const demoConfig = `apiVersion: aptify/v1alpha1
kind: Repository
url: https://apt.example.com
changelogs: true
releases:
  - name: bookworm
    version: "12"
    origin: Demo Organization
    label: Demo
    suite: bookworm
    description: Demo repository
    components:
      - name: stable
        packages:
          - testdata/package/hello-world_1.0_amd64.deb
          - testdata/package/hello-world_2.0_amd64.deb
  - name: bookworm-max-versions
    origin: Demo Organization
    label: Demo
    suite: bookworm
    components:
      - name: stable
        packages:
          - testdata/package/hello-world_*.deb
        max_versions: 1
`

// TestFromYAML pins that a demo.yaml shaped document decodes into the whole
// v1alpha1 tree: field names are matched case insensitively (url -> URL) and
// max_versions comes in through its explicit tag rather than as maxversions.
func TestFromYAML(t *testing.T) {
	conf, err := FromYAML(strings.NewReader(demoConfig))
	require.NoError(t, err)

	assert.Equal(t, latestconfig.APIVersion, conf.APIVersion)
	assert.Equal(t, "Repository", conf.Kind)
	assert.Equal(t, "https://apt.example.com", conf.URL)
	assert.True(t, conf.Changelogs)
	assert.True(t, conf.HasChangelogs())

	require.Len(t, conf.Releases, 2)

	first := conf.Releases[0]
	assert.Equal(t, "bookworm", first.Name)
	assert.Equal(t, "12", first.Version)
	assert.Equal(t, "Demo Organization", first.Origin)
	assert.Equal(t, "Demo", first.Label)
	assert.Equal(t, "bookworm", first.Suite)
	assert.Equal(t, "Demo repository", first.Description)
	require.Len(t, first.Components, 1)
	assert.Equal(t, "stable", first.Components[0].Name)
	assert.Equal(t, []string{
		"testdata/package/hello-world_1.0_amd64.deb",
		"testdata/package/hello-world_2.0_amd64.deb",
	}, first.Components[0].Packages)
	assert.Zero(t, first.Components[0].MaxVersions, "an unset max_versions keeps every version")

	second := conf.Releases[1]
	assert.Equal(t, "bookworm-max-versions", second.Name)
	require.Len(t, second.Components, 1)
	assert.Equal(t, uint(1), second.Components[0].MaxVersions)
}

// TestFromYAMLErrors pins how each way of getting the TypeMeta wrong is
// reported. A document with no apiVersion at all is not a special case: it
// takes the same "unsupported api version" arm as a misspelled one, with an
// empty version in the message.
func TestFromYAMLErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		conf    string
		wantErr string
	}{
		{
			name:    "unknown api version",
			conf:    "apiVersion: aptify/v1beta1\nkind: Repository\n",
			wantErr: "unsupported api version: aptify/v1beta1",
		},
		{
			name:    "unknown kind",
			conf:    "apiVersion: aptify/v1alpha1\nkind: Mirror\n",
			wantErr: `failed to get config by kind "Mirror": unsupported kind: Mirror`,
		},
		{
			name:    "body does not match the schema",
			conf:    "apiVersion: aptify/v1alpha1\nkind: Repository\nreleases: bookworm\n",
			wantErr: "failed to unmarshal config from config file",
		},
		{
			name:    "malformed yaml",
			conf:    "\tapiVersion: aptify/v1alpha1\n",
			wantErr: "failed to unmarshal type meta from config file",
		},
		{
			name:    "missing type meta",
			conf:    "url: https://apt.example.com\n",
			wantErr: "unsupported api version: ",
		},
		{
			name:    "empty document",
			conf:    "",
			wantErr: "unsupported api version: ",
		},
		{
			name:    "kind without api version",
			conf:    "kind: Repository\n",
			wantErr: "unsupported api version: ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := FromYAML(strings.NewReader(tc.conf))
			require.Error(t, err)
			assert.Nil(t, conf)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestFromYAMLReaderError pins that a reader which fails part way through is
// reported as a read failure rather than as a parse failure.
func TestFromYAMLReaderError(t *testing.T) {
	conf, err := FromYAML(failingReader{})
	require.Error(t, err)
	assert.Nil(t, conf)
	assert.Contains(t, err.Error(), "failed to read config from reader")
}

// TestToYAML pins that encoding stamps the TypeMeta onto a value that was built
// in Go without one, and that the result reads back as the same config.
func TestToYAML(t *testing.T) {
	conf := &latestconfig.Repository{
		URL:        "https://apt.example.com",
		Changelogs: true,
		ByHash: latestconfig.ByHashConfig{
			Enabled:   true,
			Retention: 48 * time.Hour,
		},
		Releases: []latestconfig.ReleaseConfig{{
			Name:   "bookworm",
			Origin: "Demo Organization",
			Label:  "Demo",
			Suite:  "bookworm",
			Components: []latestconfig.ComponentConfig{{
				Name:        "stable",
				Packages:    []string{"testdata/package/hello-world_*.deb"},
				MaxVersions: 2,
			}},
		}},
	}

	var sb strings.Builder
	require.NoError(t, ToYAML(&sb, conf))

	out := sb.String()
	assert.Contains(t, out, "apiVersion: aptify/v1alpha1")
	assert.Contains(t, out, "kind: Repository")
	assert.Contains(t, out, "max_versions: 2")
	assert.Equal(t, latestconfig.APIVersion, conf.APIVersion, "ToYAML populates the type meta in place")
	assert.Equal(t, "Repository", conf.Kind)

	roundTripped, err := FromYAML(strings.NewReader(out))
	require.NoError(t, err)
	assert.Equal(t, conf, roundTripped)
}

// TestToYAMLOmitsByHash pins that a repository which never mentions by-hash
// encodes without the block, so the feature stays invisible when it is off.
func TestToYAMLOmitsByHash(t *testing.T) {
	var sb strings.Builder
	require.NoError(t, ToYAML(&sb, &latestconfig.Repository{URL: "https://apt.example.com"}))

	assert.NotContains(t, sb.String(), "by_hash")
}

// TestToYAMLWriterError pins that a failing writer is surfaced rather than
// swallowed.
func TestToYAMLWriterError(t *testing.T) {
	err := ToYAML(failingWriter{}, &latestconfig.Repository{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal config")
}

// TestMigrateToLatest pins that v1alpha1 is the latest version: migrating one
// is the identity, down to the pointer, and anything else is rejected by the
// api version it reports.
func TestMigrateToLatest(t *testing.T) {
	conf := &latestconfig.Repository{URL: "https://apt.example.com"}

	migrated, err := MigrateToLatest(conf)
	require.NoError(t, err)
	assert.Same(t, conf, migrated)

	migrated, err = MigrateToLatest(&unknownConfig{})
	require.Error(t, err)
	assert.Nil(t, migrated)
	assert.Contains(t, err.Error(), "unsupported config version: aptify/v0")
}

// unknownConfig is a config version that does not exist, used to reach the
// rejection arm of MigrateToLatest.
type unknownConfig struct {
	configtypes.TypeMeta `yaml:",inline"`
}

func (c *unknownConfig) GetAPIVersion() string { return "aptify/v0" }
func (c *unknownConfig) GetKind() string       { return "Repository" }
func (c *unknownConfig) PopulateTypeMeta() {
	c.TypeMeta = configtypes.TypeMeta{APIVersion: c.GetAPIVersion(), Kind: c.GetKind()}
}

// errFailed is returned by the failing reader and writer below.
var errFailed = errors.New("failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errFailed }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errFailed }
