// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/stretchr/testify/require"
)

func TestParseAPIKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "empty string",
			raw:  "",
			want: []string{},
		},
		{
			name: "whitespace only",
			raw:  "   \n\t  \n  ",
			want: []string{},
		},
		{
			name: "single key",
			raw:  "key1",
			want: []string{"key1"},
		},
		{
			name: "single key with surrounding whitespace",
			raw:  "  key1  \n",
			want: []string{"key1"},
		},
		{
			name: "multi-line keys",
			raw:  "key1\nkey2\nkey3",
			want: []string{"key1", "key2", "key3"},
		},
		{
			name: "multi-line with empty lines and spaces",
			raw:  "\n  key1  \n\n  key2  \n  key3\n\n",
			want: []string{"key1", "key2", "key3"},
		},
		{
			name: "comma separated on single line",
			raw:  "key1, key2, key3",
			want: []string{"key1", "key2", "key3"},
		},
		{
			name: "multiple consecutive commas and whitespace",
			raw:  "key1,,,  key2, ,key3",
			want: []string{"key1", "key2", "key3"},
		},
		{
			name: "mixed comma and multi-line",
			raw:  "key1, key2\nkey3, key4\n",
			want: []string{"key1", "key2", "key3", "key4"},
		},
		{
			name: "windows crlf line endings",
			raw:  "key1\r\nkey2\r\nkey3\r\n",
			want: []string{"key1", "key2", "key3"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAPIKeys(tc.raw)
			require.Equal(t, tc.want, got)
		})
	}
}

type dummyProvider struct {
	id     string
	closed bool
}

func (d *dummyProvider) Client(ctx context.Context) (backend.Client, error) {
	return &dummyClient{id: d.id}, nil
}

func (d *dummyProvider) Models(ctx context.Context) ([]string, error) {
	return []string{"model1"}, nil
}

func (d *dummyProvider) ResolveModels(category backend.ModelCategory) []string {
	return []string{"resolved-model"}
}

func (d *dummyProvider) Close() error {
	d.closed = true
	return nil
}

type dummyClient struct {
	id string
}

func (d *dummyClient) GenerateContent(ctx context.Context, model string, cfg *backend.GenerateConfig,
	history []*backend.Message) (*backend.GenerateResponse, error) {
	return nil, nil
}

func TestRotatingProviderSequential(t *testing.T) {
	ctx := context.Background()
	p1 := &dummyProvider{id: "p1"}
	p2 := &dummyProvider{id: "p2"}
	rotator := newRotatingProvider([]backend.Provider{p1, p2})

	c1, err := rotator.Client(ctx)
	require.NoError(t, err)
	require.Equal(t, "p1", c1.(*dummyClient).id)

	c2, err := rotator.Client(ctx)
	require.NoError(t, err)
	require.Equal(t, "p2", c2.(*dummyClient).id)

	c3, err := rotator.Client(ctx)
	require.NoError(t, err)
	require.Equal(t, "p1", c3.(*dummyClient).id)

	models, err := rotator.Models(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"model1"}, models)

	require.Equal(t, []string{"resolved-model"}, rotator.ResolveModels(backend.CoreModel))

	require.NoError(t, rotator.Close())
	require.True(t, p1.closed)
	require.True(t, p2.closed)
}

func TestGeminiProviderRegistrationSingleKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEYS", "key1")
	t.Setenv("GOOGLE_API_KEYS", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	factory := providers["gemini"]
	require.NotNil(t, factory)

	prov, err := factory(context.Background(), "")
	require.NoError(t, err)
	defer prov.Close()

	_, isRotating := prov.(*rotatingProvider)
	require.False(t, isRotating)
}

func TestGeminiProviderRegistrationMultipleKeys(t *testing.T) {
	t.Setenv("GEMINI_API_KEYS", "key1\nkey2")
	t.Setenv("GOOGLE_API_KEYS", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	factory := providers["gemini"]
	require.NotNil(t, factory)

	prov, err := factory(context.Background(), "")
	require.NoError(t, err)
	defer prov.Close()

	rot, ok := prov.(*rotatingProvider)
	require.True(t, ok)
	require.Len(t, rot.providers, 2)
}

func TestGeminiProviderRegistrationNoKeys(t *testing.T) {
	t.Setenv("GEMINI_API_KEYS", "")
	t.Setenv("GOOGLE_API_KEYS", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	factory := providers["gemini"]
	require.NotNil(t, factory)

	_, err := factory(context.Background(), "")
	require.Error(t, err)
}
