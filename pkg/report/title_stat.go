// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
)

func AddTitleStat(file string, reps []*Report) error {
	var titles []string
	for _, rep := range reps {
		titles = append(titles, rep.Title)
	}
	stat, err := readStatFile(file)
	if err != nil {
		return fmt.Errorf("readStatFile: %w", err)
	}
	stat.add(titles)
	if err := writeStatFile(file, stat); err != nil {
		return fmt.Errorf("writeStatFile: %w", err)
	}
	return nil
}

func readStatFile(file string) (*titleStat, error) {
	stat := &titleStat{}
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return stat, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return stat, nil
	}
	if err := json.Unmarshal(data, stat); err != nil {
		return nil, err
	}
	return stat, nil
}

func writeStatFile(file string, stat *titleStat) error {
	data, err := json.MarshalIndent(stat, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0644); err != nil {
		return err
	}
	return nil
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
