// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package spanner

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
)

// LoadDDL loads and parses DDL statements from SQL migration files matching glob in fsys.
// If forward is true, files are sorted in ascending order (for 'up' migrations).
// If forward is false, files are sorted in descending order (for 'down' migrations).
func LoadDDL(fsys fs.FS, glob string, forward bool) ([]string, error) {
	files, err := fs.Glob(fsys, glob)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("loadDDL: glob did not match any files: %q", glob)
	}
	sortedFiles, err := sortMigrationFiles(files, forward)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, file := range sortedFiles {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		for stmt := range strings.SplitSeq(string(data), ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt != "" {
				all = append(all, stmt)
			}
		}
	}
	return all, nil
}

func sortMigrationFiles(files []string, forward bool) ([]string, error) {
	type migrationFile struct {
		num  int
		file string
	}
	var mFiles []migrationFile
	seen := map[int]string{}
	for _, file := range files {
		basename := path.Base(file)
		parts := strings.Split(basename, "_")
		num, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("migration file %v must start with a number: %w", file, err)
		}
		if old, ok := seen[num]; ok {
			return nil, fmt.Errorf("duplicate migration number %v: %v and %v", num, old, file)
		}
		seen[num] = file
		mFiles = append(mFiles, migrationFile{num: num, file: file})
	}
	slices.SortFunc(mFiles, func(a, b migrationFile) int {
		res := a.num - b.num
		if !forward {
			res = -res
		}
		return res
	})
	var result []string
	for _, f := range mFiles {
		result = append(result, f.file)
	}
	return result, nil
}

// UpdateSpannerDDL executes DDL statements on an existing Spanner database.
func UpdateSpannerDDL(ctx context.Context, uri string, ddl []string) error {
	client, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return fmt.Errorf("failed NewDatabaseAdminClient: %w", err)
	}
	defer client.Close()
	op, err := client.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Database:   uri,
		Statements: ddl,
	})
	if err != nil {
		return fmt.Errorf("failed UpdateDatabaseDdl: %w", err)
	}
	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("failed UpdateDatabaseDdl Wait: %w", err)
	}
	return nil
}
