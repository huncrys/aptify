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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// recorder builds a cli.BeforeFunc that appends its name to calls and returns
// err, so a test can assert on which hooks ran and in what order.
func recorder(calls *[]string, name string, err error) cli.BeforeFunc {
	return func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		*calls = append(*calls, name)
		return ctx, err
	}
}

// TestBeforeAllRunsInOrder pins that the hooks run left to right, each one
// seeing the command it was given, and that the combined hook succeeds.
func TestBeforeAllRunsInOrder(t *testing.T) {
	var calls []string

	cmd := &cli.Command{Name: "build"}
	var seen *cli.Command

	before := BeforeAll(
		recorder(&calls, "first", nil),
		func(ctx context.Context, c *cli.Command) (context.Context, error) {
			calls = append(calls, "second")
			seen = c
			return ctx, nil
		},
		recorder(&calls, "third", nil),
	)

	ctx := context.Background()
	got, err := before(ctx, cmd)
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second", "third"}, calls)
	assert.Same(t, cmd, seen)
	assert.Equal(t, ctx, got)
}

// TestBeforeAllShortCircuits pins that the first failure stops the chain: the
// hooks after it never run, and the error is returned unwrapped so that
// errors.Is still matches it.
func TestBeforeAllShortCircuits(t *testing.T) {
	var calls []string

	wantErr := errors.New("boom")

	before := BeforeAll(
		recorder(&calls, "first", nil),
		recorder(&calls, "second", wantErr),
		recorder(&calls, "third", nil),
	)

	_, err := before(context.Background(), &cli.Command{})
	require.Error(t, err)
	assert.Same(t, wantErr, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Equal(t, []string{"first", "second"}, calls)
}

// TestBeforeAllEmpty pins that no hooks at all is not an error, so a caller can
// build the list conditionally.
func TestBeforeAllEmpty(t *testing.T) {
	ctx := context.Background()

	got, err := BeforeAll()(ctx, &cli.Command{})
	require.NoError(t, err)
	assert.Equal(t, ctx, got)
}

// TestBeforeAllPropagatesContext pins the contract a Before hook relies on to
// set anything up for the rest of the run: the context one hook derives is what
// the hooks after it are given, and what the caller gets back. Each hook builds
// on the previous one's, so several of them compose.
func TestBeforeAllPropagatesContext(t *testing.T) {
	type firstKey struct{}
	type secondKey struct{}

	derive := func(key, value any) cli.BeforeFunc {
		return func(ctx context.Context, _ *cli.Command) (context.Context, error) {
			return context.WithValue(ctx, key, value), nil
		}
	}

	var innerSaw any
	observe := func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		innerSaw = ctx.Value(firstKey{})
		return ctx, nil
	}

	got, err := BeforeAll(
		derive(firstKey{}, "first"),
		observe,
		derive(secondKey{}, "second"),
	)(context.Background(), &cli.Command{})
	require.NoError(t, err)
	assert.Equal(t, "first", innerSaw, "a later hook sees the derived context")
	assert.Equal(t, "first", got.Value(firstKey{}), "and so does the caller")
	assert.Equal(t, "second", got.Value(secondKey{}), "every hook's context is kept")

	// The failure path returns the failing hook's own context too.
	wantErr := errors.New("boom")
	failWithContext := func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		return context.WithValue(ctx, firstKey{}, "value"), wantErr
	}

	got, err = BeforeAll(failWithContext)(context.Background(), &cli.Command{})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, "value", got.Value(firstKey{}))
}
