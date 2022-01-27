// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stats"
)

type BugInfo struct {
	Title string
}

type RunResult interface{}

// The information collected from a syz-manager instance.
type SyzManagerResult struct {
	Bugs        []BugInfo
	StatRecords []StatRecord
}

// A snapshot of syzkaller statistics at a particular time.
type StatRecord map[string]uint64

// The grouping of single instance results. Taken by all stat generating routines.
type RunResultGroup struct {
	Name    string
	Results []RunResult
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

func readBenches(benchFile string) ([]StatRecord, error) {
	f, err := os.Open(benchFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	ret := []StatRecord{}
	for dec.More() {
		curr := make(StatRecord)
		if err := dec.Decode(&curr); err == nil {
			ret = append(ret, curr)
		}
	}
	return ret, nil
}

// The input are stat snapshots of different instances taken at the same time.
// This function groups those data points per stat types (e.g. exec total, crashes, etc.).
func groupSamples(records []StatRecord) map[string]*stats.Sample {
	ret := make(map[string]*stats.Sample)
	for _, record := range records {
		for key, value := range record {
			if ret[key] == nil {
				ret[key] = &stats.Sample{}
			}
			ret[key].Xs = append(ret[key].Xs, float64(value))
		}
	}
	return ret
}

type BugSummary struct {
	title        string
	found        map[string]bool
	resultsCount map[string]int // the number of run results that have found this bug
}

// If there are several instances belonging to a single checkout, we're interested in the
// set of bugs found by at least one of those instances.
func summarizeBugs(groups []RunResultGroup) ([]*BugSummary, error) {
	bugsMap := make(map[string]*BugSummary)
	for _, group := range groups {
		for _, result := range group.SyzManagerResults() {
			for _, bug := range result.Bugs {
				summary := bugsMap[bug.Title]
				if summary == nil {
					summary = &BugSummary{
						title:        bug.Title,
						found:        make(map[string]bool),
						resultsCount: make(map[string]int),
					}
					bugsMap[bug.Title] = summary
				}
				summary.found[group.Name] = true
				summary.resultsCount[group.Name]++
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
func (view StatView) GenerateBugTable() (*Table, error) {
	table := NewTable("Bug")
	for _, group := range view.Groups {
		table.AddColumn(group.Name)
	}
	summaries, err := summarizeBugs(view.Groups)
	if err != nil {
		return nil, err
	}
	for _, bug := range summaries {
		for _, group := range view.Groups {
			if bug.found[group.Name] {
				table.Set(bug.title, group.Name, NewBoolCell(true))
			}
		}
	}
	return table, nil
}

func (view StatView) GenerateBugCountsTable() (*Table, error) {
	table := NewTable("Bug")
	for _, group := range view.Groups {
		table.AddColumn(group.Name)
	}
	summaries, err := summarizeBugs(view.Groups)
	if err != nil {
		return nil, err
	}
	for _, bug := range summaries {
		for _, group := range view.Groups {
			if bug.found[group.Name] {
				count := bug.resultsCount[group.Name]
				percent := float64(count) / float64(len(group.Results)) * 100.0
				value := fmt.Sprintf("%v (%.1f%%)", count, percent)
				table.Set(bug.title, group.Name, value)
			}
		}
	}
	return table, nil
}

func (group RunResultGroup) SyzManagerResults() []*SyzManagerResult {
	ret := []*SyzManagerResult{}
	for _, rawRes := range group.Results {
		res, ok := rawRes.(*SyzManagerResult)
		if ok {
			ret = append(ret, res)
		}
	}
	return ret
}

func (group RunResultGroup) AvgStatRecords() []map[string]uint64 {
	ret := []map[string]uint64{}
	commonLen := group.minResultLength()
	for i := 0; i < commonLen; i++ {
		record := make(map[string]uint64)
		for key, value := range group.groupNthRecord(i) {
			record[key] = uint64(value.Median())
		}
		ret = append(ret, record)
	}
	return ret
}

func (group RunResultGroup) minResultLength() int {
	if len(group.Results) == 0 {
		return 0
	}
	results := group.SyzManagerResults()
	ret := len(results[0].StatRecords)
	for _, result := range results {
		currLen := len(result.StatRecords)
		if currLen < ret {
			ret = currLen
		}
	}
	return ret
}

func (group RunResultGroup) groupNthRecord(i int) map[string]*stats.Sample {
	records := []StatRecord{}
	for _, result := range group.SyzManagerResults() {
		records = append(records, result.StatRecords[i])
	}
	return groupSamples(records)
}

func (view StatView) StatsTable() (*Table, error) {
	return view.AlignedStatsTable("uptime")
}

func (view StatView) AlignedStatsTable(field string) (*Table, error) {
	// We assume that the stats values are nonnegative.
	var commonValue float64
	for _, group := range view.Groups {
		minLen := group.minResultLength()
		if minLen == 0 {
			continue
		}
		sampleGroup := group.groupNthRecord(minLen - 1)
		sample, ok := sampleGroup[field]
		if !ok {
			return nil, fmt.Errorf("field %v is not found", field)
		}
		currValue := sample.Median()
		if currValue < commonValue || commonValue == 0 {
			commonValue = currValue
		}
	}
	table := NewTable("Property")
	cells := make(map[string]map[string]string)
	for _, group := range view.Groups {
		table.AddColumn(group.Name)
		minLen := group.minResultLength()
		if minLen == 0 {
			// Skip empty groups.
			continue
		}
		// Unwind the samples so that they are aligned on the field value.
		var samples map[string]*stats.Sample
		for i := minLen - 1; i >= 0; i-- {
			candidate := group.groupNthRecord(i)
			// TODO: consider data interpolation.
			if candidate[field].Median() >= commonValue {
				samples = candidate
			} else {
				break
			}
		}
		for key, sample := range samples {
			if _, ok := cells[key]; !ok {
				cells[key] = make(map[string]string)
			}
			table.Set(key, group.Name, NewValueCell(sample))
		}
	}
	return table, nil
}

func (view StatView) InstanceStatsTable() (*Table, error) {
	newView := StatView{}
	for _, group := range view.Groups {
		for i, result := range group.Results {
			newView.Groups = append(newView.Groups, RunResultGroup{
				Name:    fmt.Sprintf("%s-%d", group.Name, i),
				Results: []RunResult{result},
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

func (view *StatView) IsEmpty() bool {
	for _, group := range view.Groups {
		if group.minResultLength() > 0 {
			return false
		}
	}
	return true
}
