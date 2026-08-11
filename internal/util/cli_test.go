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

// TestBeforeAllDiscardsContext pins current behaviour rather than an intended
// design: BeforeAll shadows ctx inside the loop, so a context a hook derives is
// visible to neither the hooks after it nor the caller. Only the failure path
// returns a hook's context. Nothing in aptify derives a context in a Before
// hook today; if one starts to, this test is the thing that has to change with
// the fix.
func TestBeforeAllDiscardsContext(t *testing.T) {
	type ctxKey struct{}

	derive := func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		return context.WithValue(ctx, ctxKey{}, "value"), nil
	}

	var innerSaw any
	observe := func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		innerSaw = ctx.Value(ctxKey{})
		return ctx, nil
	}

	got, err := BeforeAll(derive, observe)(context.Background(), &cli.Command{})
	require.NoError(t, err)
	assert.Nil(t, innerSaw, "a later hook does not see the derived context")
	assert.Nil(t, got.Value(ctxKey{}), "nor does the caller")

	// The failure path is the one exception: it returns the failing hook's own
	// context.
	wantErr := errors.New("boom")
	failWithContext := func(ctx context.Context, _ *cli.Command) (context.Context, error) {
		return context.WithValue(ctx, ctxKey{}, "value"), wantErr
	}

	got, err = BeforeAll(failWithContext)(context.Background(), &cli.Command{})
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, "value", got.Value(ctxKey{}))
}
