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

package util

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// TestLevelFlagIsCLIValue pins that the flag still satisfies the interface
// urfave/cli parses values through; losing it would only show up at the call
// site in main.go.
func TestLevelFlagIsCLIValue(t *testing.T) {
	var _ cli.Value = (*LevelFlag)(nil)
}

// TestLevelFlagSet pins what a user may type on the command line. Case does not
// matter, and slog's offset syntax comes along for free because Set defers to
// slog.Level.UnmarshalText.
func TestLevelFlagSet(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  slog.Level
	}{
		{value: "debug", want: slog.LevelDebug},
		{value: "DEBUG", want: slog.LevelDebug},
		{value: "Debug", want: slog.LevelDebug},
		{value: "info", want: slog.LevelInfo},
		{value: "warn", want: slog.LevelWarn},
		{value: "WARN", want: slog.LevelWarn},
		{value: "error", want: slog.LevelError},
		{value: "warn+2", want: slog.LevelWarn + 2},
		{value: "debug-1", want: slog.LevelDebug - 1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			f := FromSlogLevel(slog.LevelInfo)
			require.NoError(t, f.Set(tc.value))

			assert.Equal(t, tc.want, slog.Level(*f))
		})
	}
}

// TestLevelFlagSetInvalid pins that a value slog cannot parse is rejected and
// leaves the flag at whatever it already held, so a bad --log-level does not
// silently reset the verbosity.
func TestLevelFlagSetInvalid(t *testing.T) {
	for _, value := range []string{"", "verbose", "trace", "warn+x", "9"} {
		t.Run(value, func(t *testing.T) {
			f := FromSlogLevel(slog.LevelWarn)
			require.Error(t, f.Set(value))

			assert.Equal(t, slog.LevelWarn, slog.Level(*f), "the previous level survives")
		})
	}
}

// TestLevelFlagString pins the rendering urfave/cli shows in help output and
// error messages - slog's own names, offsets included.
func TestLevelFlagString(t *testing.T) {
	for _, tc := range []struct {
		level slog.Level
		want  string
	}{
		{level: slog.LevelDebug, want: "DEBUG"},
		{level: slog.LevelInfo, want: "INFO"},
		{level: slog.LevelWarn, want: "WARN"},
		{level: slog.LevelError, want: "ERROR"},
		{level: slog.LevelWarn + 2, want: "WARN+2"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, FromSlogLevel(tc.level).String())
		})
	}
}

// TestLevelFlagGet pins that Get hands back the flag itself rather than a
// slog.Level: callers convert with slog.Level(*f), which is what main.go does.
func TestLevelFlagGet(t *testing.T) {
	f := FromSlogLevel(slog.LevelDebug)

	got := f.Get()
	require.IsType(t, (*LevelFlag)(nil), got)
	assert.Same(t, f, got)
	assert.Equal(t, slog.LevelDebug, slog.Level(*got.(*LevelFlag)))
}

// TestFromSlogLevel pins that the constructor copies: mutating the flag through
// Set does not reach back into whatever level it was built from, and two flags
// built from the same level are independent.
func TestFromSlogLevel(t *testing.T) {
	level := slog.LevelInfo

	first := FromSlogLevel(level)
	second := FromSlogLevel(level)
	require.NotSame(t, first, second)

	require.NoError(t, first.Set("error"))
	assert.Equal(t, slog.LevelError, slog.Level(*first))
	assert.Equal(t, slog.LevelInfo, slog.Level(*second))
	assert.Equal(t, slog.LevelInfo, level, "the source level is untouched")
}
