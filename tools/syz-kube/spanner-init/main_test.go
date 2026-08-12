// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/coveragedb"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
	"github.com/stretchr/testify/require"
)

func TestSpannerInitSchema(t *testing.T) {
	uri := "projects/syzkaller/instances/syzkaller/databases/coverage"
	parsedURI, err := pkgspanner.ParseURI(uri)
	require.NoError(t, err)
	require.Equal(t, "syzkaller", parsedURI.Project)
	require.Equal(t, "syzkaller", parsedURI.Instance)
	require.Equal(t, "coverage", parsedURI.Database)

	schema, err := coveragedb.GetSchema()
	require.NoError(t, err)
	require.NotEmpty(t, schema)
}
