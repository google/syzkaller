// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrcaRouterProviderRegistration(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "test-orcarouter-key-not-real")
	factory := providers["orcarouter"]
	require.NotNil(t, factory, "orcarouter must be a first-class CLI provider")
	provider, err := factory(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.NoError(t, provider.Close())
}

func TestOrcaRouterProviderRequiresKey(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	factory := providers["orcarouter"]
	require.NotNil(t, factory)
	_, err := factory(context.Background(), "")
	require.ErrorContains(t, err, "ORCAROUTER_API_KEY")
}
