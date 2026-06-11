// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"embed"

	pkgspanner "github.com/google/syzkaller/pkg/spanner"
)

//go:embed migrations/*.sql
var migrationsFs embed.FS

// GetSchema returns the DDL statements for initializing the Spanner database.
func GetSchema() ([]string, error) {
	return pkgspanner.LoadDDL(migrationsFs, "migrations/*.up.sql", true)
}

// GetDownSchema returns the DDL statements for rolling back the Spanner database.
func GetDownSchema() ([]string, error) {
	return pkgspanner.LoadDDL(migrationsFs, "migrations/*.down.sql", false)
}
