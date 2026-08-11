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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFormatMtime pins the wire format rclone and s3cmd read: Unix seconds,
// with a fraction only when there is one.
func TestFormatMtime(t *testing.T) {
	for _, tc := range []struct {
		name string
		time time.Time
		want string
	}{
		{"whole seconds", time.Unix(1481478242, 0), "1481478242"},
		{"nanoseconds", time.Unix(1481478242, 702218729), "1481478242.702218729"},
		{"a trailing zero is not part of the fraction", time.Unix(1481478242, 500000000), "1481478242.5"},
		{"leading zeroes are", time.Unix(1481478242, 1), "1481478242.000000001"},
		{"before the epoch", time.Unix(-1, 0), "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, formatMtime(tc.time))
		})
	}
}

// TestParseMtime covers what other tools write, which is what a repository
// uploaded by rclone or s3cmd carries.
func TestParseMtime(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Time
	}{
		{"whole seconds", "1481478242", time.Unix(1481478242, 0)},
		{"nanoseconds", "1481478242.702218729", time.Unix(1481478242, 702218729)},
		// The fraction is a fraction, so a short one is padded rather than
		// read as a count of nanoseconds.
		{"milliseconds", "1481478242.5", time.Unix(1481478242, 500000000)},
		{"more precision than a nanosecond", "1481478242.7022187294", time.Unix(1481478242, 702218729)},
		{"before the epoch", "-1", time.Unix(-1, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseMtime(tc.raw)
			require.True(t, ok)
			assert.True(t, got.Equal(tc.want), "got %s, want %s", got, tc.want)
		})
	}
}

// TestParseMtimeRejectsRubbish pins that an unreadable value is reported as
// such rather than as the epoch, so the caller can fall back to the object's
// own LastModified.
func TestParseMtimeRejectsRubbish(t *testing.T) {
	for _, raw := range []string{"", "yesterday", "1481478242.abc", "1.2.3", "0x10"} {
		_, ok := parseMtime(raw)
		assert.False(t, ok, "%q", raw)
	}
}

// TestMtimeRoundTrip checks the two halves against each other at the precision
// the pipeline cares about: a published file keeps the modification time it
// was published with.
func TestMtimeRoundTrip(t *testing.T) {
	for _, want := range []time.Time{
		time.Unix(0, 0),
		time.Unix(1481478242, 0),
		time.Unix(1481478242, 702218729),
		time.Unix(1481478242, 1),
		time.Now().Truncate(time.Nanosecond),
	} {
		got, ok := parseMtime(formatMtime(want))
		require.True(t, ok, "%s", want)
		assert.True(t, got.Equal(want), "got %s, want %s", got, want)
	}
}
