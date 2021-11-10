// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
)

type BugInfo struct {
	Title string
}

// The information collected from a syz-manager instance.
type RunResult struct {
	Workdir     string
	Bugs        []BugInfo
	StatRecords []map[string]uint64
}

// The grouping of single instance results. Taken by all stat generating routines.
type RunResultGroup struct {
	Name    string
	Results []*RunResult
}

// Different "views" of the statistics, e.g. only completed instances or completed + running.
type StatView struct {
	Name   string
	Groups []RunResultGroup
}

// TODO: we're implementing this functionaity at least the 3rd time (see syz-manager/html
// and tools/reporter). Create a more generic implementation and put it into a globally
// visible package.
func collectBugs(workdir string) ([]BugInfo, error) {
	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	bugs := []BugInfo{}
	for _, dir := range dirs {
		titleBytes, err := ioutil.ReadFile(filepath.Join(crashdir, dir, "description"))
		if err != nil {
			return nil, err
		}
		title := strings.TrimSpace(string(titleBytes))
		bugs = append(bugs, BugInfo{title})
	}
	return bugs, nil
}

func readBenches(benchFile string) ([]map[string]uint64, error) {
	f, err := os.Open(benchFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	ret := []map[string]uint64{}
	for dec.More() {
		curr := make(map[string]uint64)
		if err := dec.Decode(&curr); err == nil {
			ret = append(ret, curr)
		}
	}
	return ret, nil
}

func avgBenches(infos []map[string]uint64) map[string]uint64 {
	ret := make(map[string]uint64)
	if len(infos) == 0 {
		return ret
	}
	for _, stat := range infos {
		for key, value := range stat {
			ret[key] += value
		}
	}
	for key, value := range ret {
		ret[key] = value / uint64(len(infos))
	}
	return ret
}

type BugSummary struct {
	title string
	found map[string]bool
}

// If there are several instances belonging to a single checkout, we're interested in the
// set of bugs found by at least one of those instances.
func summarizeBugs(groups []RunResultGroup) ([]*BugSummary, error) {
	bugsMap := make(map[string]*BugSummary)
	for _, group := range groups {
		for _, result := range group.Results {
			for _, bug := range result.Bugs {
				summary := bugsMap[bug.Title]
				if summary == nil {
					summary = &BugSummary{
						title: bug.Title,
						found: make(map[string]bool),
					}
					bugsMap[bug.Title] = summary
				}
				summary.found[group.Name] = true
			}
		}
	}
	summaries := []*BugSummary{}
	for _, value := range bugsMap {
		summaries = append(summaries, value)
	}
	return summaries, nil
}

// For each checkout, take the union of sets of bugs found by each instance.
// Then output these unions as a single table.
func (view StatView) GenerateBugTable() ([][]string, error) {
	table := [][]string{}
	titles := []string{""}
	for _, group := range view.Groups {
		titles = append(titles, group.Name)
	}
	summaries, err := summarizeBugs(view.Groups)
	if err != nil {
		return nil, err
	}

	table = append(table, titles)
	for _, bug := range summaries {
		row := []string{bug.title}
		for _, group := range view.Groups {
			val := ""
			if bug.found[group.Name] {
				val = "YES"
			}
			row = append(row, val)
		}
		table = append(table, row)
	}
	return table, nil
}

func (group RunResultGroup) AvgStatRecords() []map[string]uint64 {
	ret := []map[string]uint64{}
	for i := 0; ; i++ {
		toAvg := []map[string]uint64{}
		for _, result := range group.Results {
			if i < len(result.StatRecords) {
				toAvg = append(toAvg, result.StatRecords[i])
			}
		}
		if len(toAvg) != len(group.Results) || len(toAvg) == 0 {
			break
		}
		ret = append(ret, avgBenches(toAvg))
	}
	return ret
}

func (view StatView) StatsTable() ([][]string, error) {
	// Ensure that everything is at the same point in time.
	avgs := make(map[string][]map[string]uint64)
	commonLength := 0
	for _, group := range view.Groups {
		records := group.AvgStatRecords()
		if len(records) == 0 {
			continue
		}
		if commonLength > len(records) || commonLength == 0 {
			commonLength = len(records)
		}
		avgs[group.Name] = records
	}

	// Map: stats key x group name -> value.
	cells := make(map[string]map[string]string)
	for name, avg := range avgs {
		for key, value := range avg[commonLength-1] {
			if _, ok := cells[key]; !ok {
				cells[key] = make(map[string]string)
			}
			cells[key][name] = fmt.Sprintf("%d", value)
		}
	}
	title := []string{""}
	for _, group := range view.Groups {
		title = append(title, group.Name)
	}
	table := [][]string{title}
	for key, valuesMap := range cells {
		row := []string{key}
		for _, group := range view.Groups {
			row = append(row, valuesMap[group.Name])
		}
		table = append(table, row)
	}
	return table, nil
}

func (view StatView) InstanceStatsTable() ([][]string, error) {
	newView := StatView{}
	for _, group := range view.Groups {
		for i, result := range group.Results {
			newView.Groups = append(newView.Groups, RunResultGroup{
				Name:    fmt.Sprintf("%s-%d", group.Name, i),
				Results: []*RunResult{result},
			})
		}
	}
	return newView.StatsTable()
}

// Average bench files of several instances into a single bench file.
func (group *RunResultGroup) SaveAvgBenchFile(fileName string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, averaged := range group.AvgStatRecords() {
		data, err := json.MarshalIndent(averaged, "", "  ")
		if err != nil {
			return err
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func (view *StatView) SaveAvgBenches(benchDir string) ([]string, error) {
	files := []string{}
	for _, group := range view.Groups {
		fileName := filepath.Join(benchDir, fmt.Sprintf("avg_%v.txt", group.Name))
		err := group.SaveAvgBenchFile(fileName)
		if err != nil {
			return nil, err
		}
		files = append(files, fileName)
	}
	return files, nil
}

func SaveTableAsCsv(table [][]string, fileName string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	return csv.NewWriter(f).WriteAll(table)
}
