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

func avgStats(infos []map[string]uint64) map[string]uint64 {
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
	found map[*CheckoutInfo]bool
}

// If there are several instances belonging to a single checkout, we're interested in the
// set of bugs found by at least one of those instances.
func summarizeBugs(checkouts []*CheckoutInfo) ([]*BugSummary, error) {
	bugsMap := make(map[string]*BugSummary)
	for _, checkout := range checkouts {
		for _, instance := range checkout.Instances {
			bugs, err := collectBugs(instance.Workdir)
			if err != nil {
				return nil, err
			}
			for _, bug := range bugs {
				summary := bugsMap[bug.Title]
				if summary == nil {
					summary = &BugSummary{
						title: bug.Title,
						found: make(map[*CheckoutInfo]bool),
					}
					bugsMap[bug.Title] = summary
				}
				summary.found[checkout] = true
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
func generateBugTable(checkouts []*CheckoutInfo) ([][]string, error) {
	table := [][]string{}
	titles := []string{""}
	for _, checkout := range checkouts {
		titles = append(titles, checkout.Name)
	}
	summaries, err := summarizeBugs(checkouts)
	if err != nil {
		return nil, err
	}

	table = append(table, titles)
	for _, bug := range summaries {
		row := []string{bug.title}
		for _, checkout := range checkouts {
			val := ""
			if bug.found[checkout] {
				val = "YES"
			}
			row = append(row, val)
		}
		table = append(table, row)
	}
	return table, nil
}

type StatGroup struct {
	Name      string
	Instances []InstanceInfo
}

func genericStatsTable(groups []StatGroup) ([][]string, error) {
	// Map: stats key x group name -> value.
	cells := make(map[string]map[string]string)
	for _, group := range groups {
		infos := []map[string]uint64{}
		for _, instance := range group.Instances {
			records, err := readBenches(instance.BenchFile)
			if err != nil {
				return nil, err
			}
			if len(records) > 0 {
				infos = append(infos, records[len(records)-1])
			}
		}
		for key, value := range avgStats(infos) {
			if _, ok := cells[key]; !ok {
				cells[key] = make(map[string]string)
			}
			cells[key][group.Name] = fmt.Sprintf("%d", value)
		}
	}
	title := []string{""}
	for _, group := range groups {
		title = append(title, group.Name)
	}
	table := [][]string{title}
	for key, valuesMap := range cells {
		row := []string{key}
		for _, group := range groups {
			row = append(row, valuesMap[group.Name])
		}
		table = append(table, row)
	}
	return table, nil
}

func checkoutStatsTable(checkouts []*CheckoutInfo) ([][]string, error) {
	groups := []StatGroup{}
	for _, checkout := range checkouts {
		groups = append(groups, StatGroup{
			Name:      checkout.Name,
			Instances: checkout.Instances,
		})
	}
	return genericStatsTable(groups)
}

func instanceStatsTable(checkouts []*CheckoutInfo) ([][]string, error) {
	groups := []StatGroup{}
	for _, checkout := range checkouts {
		for _, instance := range checkout.Instances {
			groups = append(groups, StatGroup{
				Name:      instance.Name,
				Instances: []InstanceInfo{instance},
			})
		}
	}
	return genericStatsTable(groups)
}

// Average bench files of several instances into a single bench file.
func saveAvgBenchFile(checkout *CheckoutInfo, fileName string) error {
	allRecords := [][]map[string]uint64{}
	for _, instance := range checkout.Instances {
		records, err := readBenches(instance.BenchFile)
		if err != nil {
			return err
		}
		allRecords = append(allRecords, records)
	}
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	for i := 0; ; i++ {
		toAvg := []map[string]uint64{}
		for _, records := range allRecords {
			if i < len(records) {
				toAvg = append(toAvg, records[i])
			}
		}
		if len(toAvg) != len(allRecords) {
			break
		}
		averaged := avgStats(toAvg)
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

func saveTableAsCsv(table [][]string, fileName string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	return csv.NewWriter(f).WriteAll(table)
}
