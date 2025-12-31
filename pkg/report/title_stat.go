// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"maps"

	"github.com/google/syzkaller/pkg/osutil"
)

func AddTitleStat(file string, reps []*Report) error {
	var titles []string
	for _, rep := range reps {
		titles = append(titles, rep.Title)
	}
	stat, err := ReadStatFile(file)
	if err != nil {
		return fmt.Errorf("report.ReadStatFile: %w", err)
	}
	stat.add(titles)
	if err := osutil.WriteJSON(file, stat); err != nil {
		return fmt.Errorf("writeStatFile: %w", err)
	}
	return nil
}

func ReadStatFile(file string) (*titleStat, error) {
	if !osutil.IsExist(file) {
		return &titleStat{}, nil
	}
	stat, err := osutil.ReadJSON[titleStat](file)
	return &stat, err
}

type titleStatNodes map[string]*titleStat

type titleStat struct {
	Count int
	Nodes titleStatNodes
}

func (ts *titleStat) add(reps []string) {
	if len(reps) == 0 {
		return
	}
	if ts.Nodes == nil {
		ts.Nodes = make(titleStatNodes)
	}
	if ts.Nodes[reps[0]] == nil {
		ts.Nodes[reps[0]] = &titleStat{}
	}
	ts.Nodes[reps[0]].Count++
	ts.Nodes[reps[0]].add(reps[1:])
}

func (ts *titleStat) visit(cb func(int, ...string), titles ...string) {
	if len(ts.Nodes) == 0 {
		cb(ts.Count, titles...)
		return
	}
	for title := range maps.Keys(ts.Nodes) {
		ts.Nodes[title].visit(cb, append(titles, title)...)
	}
}
