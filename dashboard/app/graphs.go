// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
)

type uiKernelHealthPage struct {
	Header *uiHeader
	Graph  *uiGraph
}

type uiBugLifetimesPage struct {
	Header    *uiHeader
	Lifetimes []uiBugLifetime
}

type uiBugLifetime struct {
	Reported     time.Time
	Fixed        float32
	Fixed1y      float32
	NotFixed     float32
	Introduced   float32
	Introduced1y float32
}

type uiManagersPage struct {
	Header   *uiHeader
	Managers *uiCheckbox
	Metrics  *uiCheckbox
	Months   *uiSlider
	Graph    *uiGraph
}

type uiGraph struct {
	Headers []string
	Columns []uiGraphColumn
}

type uiGraphColumn struct {
	Hint string
	Vals []uiGraphValue
}

type uiGraphValue struct {
	Val  float32
	Hint string
}

type uiCheckbox struct {
	ID      string
	Caption string
	Values  []*uiCheckboxValue
	vals    []string
}

type uiCheckboxValue struct {
	ID       string
	Caption  string
	Selected bool
}

type uiSlider struct {
	ID      string
	Caption string
	Val     int
	Min     int
	Max     int
}

// nolint: dupl
func handleKernelHealthGraph(c context.Context, w http.ResponseWriter, r *http.Request) error {
	accessLevel := accessLevel(c, r)
	if accessLevel != AccessAdmin {
		return ErrAccess
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	bugs, err := loadGraphBugs(c, hdr.Namespace)
	if err != nil {
		return err
	}
	data := &uiKernelHealthPage{
		Header: hdr,
		Graph:  createBugsGraph(c, bugs),
	}
	return serveTemplate(w, "graph_bugs.html", data)
}

// nolint: dupl
func handleGraphLifetimes(c context.Context, w http.ResponseWriter, r *http.Request) error {
	accessLevel := accessLevel(c, r)
	if accessLevel != AccessAdmin {
		return ErrAccess
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	bugs, err := loadGraphBugs(c, hdr.Namespace)
	if err != nil {
		return err
	}

	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Namespace=", hdr.Namespace).
		GetAll(c, &jobs)
	if err != nil {
		return err
	}
	causeBisects := make(map[string]*Job)
	for i, job := range jobs {
		if job.Type != JobBisectCause || len(job.Commits) != 1 {
			continue
		}
		causeBisects[keys[i].Parent().StringID()] = job
	}
	data := &uiBugLifetimesPage{
		Header:    hdr,
		Lifetimes: createBugLifetimes(c, bugs, causeBisects),
	}
	return serveTemplate(w, "graph_lifetimes.html", data)
}

func loadGraphBugs(c context.Context, ns string) ([]*Bug, error) {
	filter := func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	}
	bugs, _, err := loadAllBugs(c, filter)
	if err != nil {
		return nil, err
	}
	n := 0
	fixes := make(map[string]bool)
	lastReporting := config.Namespaces[ns].lastActiveReporting()
	for _, bug := range bugs {
		if bug.Status >= BugStatusInvalid {
			continue
		}
		if bug.Status == BugStatusOpen && bug.Reporting[lastReporting].Reported.IsZero() {
			continue
		}
		dup := false
		for _, com := range bug.Commits {
			if fixes[com] {
				dup = true
			}
			fixes[com] = true
		}
		if dup {
			continue
		}
		bugs[n] = bug
		n++
	}
	return bugs[:n], nil
}

func createBugsGraph(c context.Context, bugs []*Bug) *uiGraph {
	type BugStats struct {
		Opened        int
		Fixed         int
		TotalReported int
		TotalOpen     int
		TotalFixed    int
	}
	const timeWeek = 30 * 24 * time.Hour
	now := timeNow(c)
	m := make(map[int]*BugStats)
	maxWeek := 0
	bugStatsFor := func(t time.Time) *BugStats {
		week := int(now.Sub(t) / (30 * 24 * time.Hour))
		if week < 0 {
			week = 0
		}
		if maxWeek < week {
			maxWeek = week
		}
		bs := m[week]
		if bs == nil {
			bs = new(BugStats)
			m[week] = bs
		}
		return bs
	}
	for _, bug := range bugs {
		bugStatsFor(bug.FirstTime).Opened++
		if !bug.Closed.IsZero() {
			bugStatsFor(bug.Closed).Fixed++
		} else if len(bug.Commits) != 0 {
			bugStatsFor(now).Fixed++
		}
	}
	var stats []BugStats
	var prev BugStats
	for i := maxWeek; i >= 0; i-- {
		var bs BugStats
		if p := m[i]; p != nil {
			bs = *p
		}
		bs.TotalReported = prev.TotalReported + bs.Opened
		bs.TotalFixed = prev.TotalFixed + bs.Fixed
		bs.TotalOpen = bs.TotalReported - bs.TotalFixed
		stats = append(stats, bs)
		prev = bs
	}
	var columns []uiGraphColumn
	for week, bs := range stats {
		col := uiGraphColumn{Hint: now.Add(time.Duration(week-len(stats)+1) * timeWeek).Format("Jan-06")}
		col.Vals = append(col.Vals, uiGraphValue{Val: float32(bs.TotalOpen)})
		col.Vals = append(col.Vals, uiGraphValue{Val: float32(bs.TotalReported)})
		col.Vals = append(col.Vals, uiGraphValue{Val: float32(bs.TotalFixed)})
		// col.Vals = append(col.Vals, uiGraphValue{Val: float32(bs.Opened)})
		// col.Vals = append(col.Vals, uiGraphValue{Val: float32(bs.Fixed)})
		columns = append(columns, col)
	}
	return &uiGraph{
		Headers: []string{"open bugs", "total reported", "total fixed"},
		Columns: columns,
	}
}

func createBugLifetimes(c context.Context, bugs []*Bug, causeBisects map[string]*Job) []uiBugLifetime {
	var res []uiBugLifetime
	for i, bug := range bugs {
		ui := uiBugLifetime{
			// TODO: this is not the time when it was reported to the final reporting.
			Reported: bug.FirstTime,
		}
		fixed := bug.FixTime
		if fixed.IsZero() || bug.Status == BugStatusFixed && bug.Closed.Before(fixed) {
			fixed = bug.Closed
		}
		if !fixed.IsZero() {
			days := float32(fixed.Sub(ui.Reported)) / float32(24*time.Hour)
			if days > 365 {
				ui.Fixed1y = 365 + float32(i%7)
			} else {
				if days <= 0 {
					days = 0.1
				}
				ui.Fixed = days
			}
		} else {
			ui.NotFixed = 400 - float32(i%7)
		}
		if job := causeBisects[bug.keyHash()]; job != nil {
			days := float32(job.Commits[0].Date.Sub(ui.Reported)) / float32(24*time.Hour)
			if days < -365 {
				ui.Introduced1y = -365 - float32(i%7)
			} else {
				if days >= 0 {
					days = -0.1
				}
				ui.Introduced = days
			}
		}
		res = append(res, ui)
	}
	return res
}

func handleGraphFuzzing(c context.Context, w http.ResponseWriter, r *http.Request) error {
	accessLevel := accessLevel(c, r)
	if accessLevel != AccessAdmin {
		return ErrAccess
	}
	hdr, err := commonHeader(c, r, w, "")
	if err != nil {
		return err
	}
	r.ParseForm()

	allManagers, err := managerList(c, hdr.Namespace)
	if err != nil {
		return err
	}
	data := &uiManagersPage{
		Header:   hdr,
		Managers: createCheckBox(r, "Instances", allManagers),
		Metrics: createCheckBox(r, "Metrics", []string{
			"MaxCorpus", "MaxCover", "MaxPCs", "TotalFuzzingTime",
			"TotalCrashes", "CrashTypes", "SuppressedCrashes", "TotalExecs",
			"ExecsPerSec"}),
		Months: createSlider(r, "Months", 1, 36),
	}
	data.Graph, err = createManagersGraph(c, hdr.Namespace, data.Managers.vals, data.Metrics.vals, data.Months.Val*30)
	if err != nil {
		return err
	}
	return serveTemplate(w, "graph_fuzzing.html", data)
}

func createManagersGraph(c context.Context, ns string, selManagers, selMetrics []string, days int) (*uiGraph, error) {
	graph := &uiGraph{}
	for _, mgr := range selManagers {
		for _, metric := range selMetrics {
			graph.Headers = append(graph.Headers, mgr+"-"+metric)
		}
	}
	now := timeNow(c)
	const day = 24 * time.Hour
	// Step 1: fill the whole table with empty values to simplify subsequent logic
	// when we fill random positions in the table.
	for date := 0; date <= days; date++ {
		col := uiGraphColumn{Hint: now.Add(time.Duration(date-days) * day).Format("02-01-2006")}
		for range selManagers {
			for range selMetrics {
				col.Vals = append(col.Vals, uiGraphValue{Hint: "-"})
			}
		}
		graph.Columns = append(graph.Columns, col)
	}
	// Step 2: fill in actual data.
	for mgrIndex, mgr := range selManagers {
		parentKey := mgrKey(c, ns, mgr)
		var stats []*ManagerStats
		_, err := db.NewQuery("ManagerStats").
			Ancestor(parentKey).
			GetAll(c, &stats)
		if err != nil {
			return nil, err
		}
		for _, stat := range stats {
			dayIndex := days - int(now.Sub(dateTime(stat.Date))/day)
			if dayIndex < 0 || dayIndex > days {
				continue
			}
			for metricIndex, metric := range selMetrics {
				val := extractMetric(stat, metric)
				graph.Columns[dayIndex].Vals[mgrIndex*len(selMetrics)+metricIndex] = uiGraphValue{
					Val:  float32(val),
					Hint: fmt.Sprintf("%.2f", val),
				}
			}
		}
	}
	// Step 3: normalize data to [0..100] range.
	// We visualize radically different values and they all should fit into a single graph.
	// We normalize the same metric across all managers so that a single metric is still
	// comparable across different managers.
	if len(selMetrics) > 1 {
		for metricIndex := range selMetrics {
			max := float32(1)
			for col := range graph.Columns {
				for mgrIndex := range selManagers {
					val := graph.Columns[col].Vals[mgrIndex*len(selMetrics)+metricIndex].Val
					if max < val {
						max = val
					}
				}
			}
			for col := range graph.Columns {
				for mgrIndex := range selManagers {
					graph.Columns[col].Vals[mgrIndex*len(selMetrics)+metricIndex].Val /= max * 100
				}
			}
		}
	}
	return graph, nil
}

func extractMetric(stat *ManagerStats, metric string) float64 {
	switch metric {
	case "MaxCorpus":
		return float64(stat.MaxCorpus)
	case "MaxCover":
		return float64(stat.MaxCover)
	case "MaxPCs":
		return float64(stat.MaxPCs)
	case "TotalFuzzingTime":
		return float64(stat.TotalFuzzingTime)
	case "TotalCrashes":
		return float64(stat.TotalCrashes)
	case "CrashTypes":
		return float64(stat.CrashTypes)
	case "SuppressedCrashes":
		return float64(stat.SuppressedCrashes)
	case "TotalExecs":
		return float64(stat.TotalExecs)
	case "ExecsPerSec":
		timeSec := float64(stat.TotalFuzzingTime) / 1e9
		if timeSec == 0 {
			return 0
		}
		return float64(stat.TotalExecs) / timeSec
	default:
		panic(fmt.Sprintf("unknown metric %q", metric))
	}
}

func createCheckBox(r *http.Request, caption string, values []string) *uiCheckbox {
	// TODO: turn this into proper ID that can be used in HTML.
	id := caption
	ui := &uiCheckbox{
		ID:      id,
		Caption: caption,
		vals:    r.Form[id],
	}
	// TODO: filter selMetrics against allMetrics.
	if len(ui.vals) == 0 {
		ui.vals = []string{values[0]}
	}
	for _, val := range values {
		ui.Values = append(ui.Values, &uiCheckboxValue{
			ID: val,
			// TODO: use this as caption and form ID.
			Selected: stringInList(ui.vals, val),
		})
	}
	return ui
}

func createSlider(r *http.Request, caption string, min, max int) *uiSlider {
	// TODO: turn this into proper ID that can be used in HTML.
	id := caption
	ui := &uiSlider{
		ID:      id,
		Caption: caption,
		Val:     min,
		Min:     min,
		Max:     max,
	}
	if val, _ := strconv.Atoi(r.FormValue(id)); val >= min && val <= max {
		ui.Val = val
	}
	return ui
}
