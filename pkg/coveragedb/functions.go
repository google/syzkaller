// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"google.golang.org/api/iterator"
)

// FuncLines represents the 'functions' table records.
// It could be used to maps 'hitcounts' from 'files' table to the function names.
type FuncLines struct {
	FilePath string
	FuncName string
	Lines    []int64 // List of lines we know belong to this function name according to the addr2line output.
}

func MakeFuncFinder(ctx context.Context, client spannerclient.SpannerClient, ns string, timePeriod TimePeriod,
) (*FunctionFinder, error) {
	stmt := spanner.Statement{
		SQL: `select
    filepath, funcname, lines
from merge_history
  join functions
    on merge_history.session = functions.session
where
  merge_history.namespace=$1 and dateto=$2 and duration=$3`,
		Params: map[string]interface{}{
			"p1": ns,
			"p2": timePeriod.DateTo,
			"p3": timePeriod.Days,
		},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	ff := &FunctionFinder{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("iter.Next(): %w", err)
		}
		var r FuncLines
		if err = row.ToStruct(&r); err != nil {
			return nil, fmt.Errorf("row.ToStruct(): %w", err)
		}

		for _, val := range r.Lines {
			ff.addLine(r.FilePath, r.FuncName, int(val))
		}
	}
	return ff, nil
}

type FunctionFinder struct {
	fileLineToFuncName map[string]map[int]string
}

func (ff *FunctionFinder) addLine(fileName, funcName string, line int) {
	if ff.fileLineToFuncName == nil {
		ff.fileLineToFuncName = map[string]map[int]string{}
	}
	if ff.fileLineToFuncName[fileName] == nil {
		ff.fileLineToFuncName[fileName] = map[int]string{}
	}
	ff.fileLineToFuncName[fileName][line] = funcName
}

func (ff *FunctionFinder) FileLineToFuncName(filePath string, line int) (string, error) {
	if _, ok := ff.fileLineToFuncName[filePath]; !ok {
		return "", fmt.Errorf("file %s not found", filePath)
	}
	if _, ok := ff.fileLineToFuncName[filePath][line]; !ok {
		return "", fmt.Errorf("file:line %s:%d function not found", filePath, line)
	}
	return ff.fileLineToFuncName[filePath][line], nil
}
