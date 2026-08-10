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
	"strings"
	"testing"
	"time"
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
