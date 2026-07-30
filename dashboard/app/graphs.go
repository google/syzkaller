// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/report/crash"
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

type uiResolutionPage struct {
	Header *uiHeader
	Graph  *uiGraph
}

type uiHistogramPage struct {
	Title  string
	Header *uiHeader
	Graph  *uiGraph
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

type uiCrashesPage struct {
	Header      *uiHeader
	Graph       *uiGraph
	Regexps     *uiMultiInput
	GraphMonths *uiSlider
	TableDays   *uiSlider
	Table       *uiCrashPageTable
}

type uiGraph struct {
	Headers []uiGraphHeader
	Columns []uiGraphColumn
}

type uiGraphHeader struct {
	Name  string
	Color string
}

type uiGraphColumn struct {
	Hint       string
	Annotation float32
	Vals       []uiGraphValue
}

type uiGraphValue struct {
	Val    float32
	IsNull bool
	Hint   string
}

type uiCrashPageTable struct {
	Title string
	Rows  []*uiCrashSummary
}

type uiCrashSummary struct {
	Title     string
	Link      string
	Count     int
	Share     float32
	GraphLink string
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

type uiMultiInput struct {
	ID      string
	Caption string
	Vals    []string
}

func handleKernelHealthGraph(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	bugs, err := loadGraphBugs(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	data := &uiKernelHealthPage{
		Header: hdr,
		Graph:  createBugsGraph(ctx, bugs),
	}
	return serveTemplate(w, "graph_bugs.html", data)
}

func handleGraphLifetimes(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	bugs, err := loadGraphBugs(ctx, hdr.Namespace)
	if err != nil {
		return err
	}

	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Namespace=", hdr.Namespace).
		Filter("Type=", JobBisectCause).
		GetAll(ctx, &jobs)
	if err != nil {
		return err
	}
	causeBisects := make(map[string]*Job)
	for i, job := range jobs {
		if len(job.Commits) != 1 {
			continue
		}
		causeBisects[keys[i].Parent().StringID()] = job
	}
	data := &uiBugLifetimesPage{
		Header:    hdr,
		Lifetimes: createBugLifetimes(ctx, bugs, causeBisects),
	}
	return serveTemplate(w, "graph_lifetimes.html", data)
}

func foundBugsGraphKey(ns string) string {
	return fmt.Sprintf("%s-found-bugs-graph", ns)
}

func CachedFoundBugsGraph(ctx context.Context, ns string) (*uiGraph, error) {
	return cachedObject(ctx,
		foundBugsGraphKey(ns),
		6*time.Hour,
		func(ctx context.Context) (*uiGraph, error) {
			bugs, err := loadStableGraphBugs(ctx, ns)
			if err != nil {
				return nil, err
			}
			return createFoundBugs(ctx, bugs), nil
		},
	)
}

func handleFoundBugsGraph(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	graph, err := CachedFoundBugsGraph(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	data := &uiHistogramPage{
		Title:  hdr.Namespace + " bugs found per month",
		Header: hdr,
		Graph:  graph,
	}
	return serveTemplate(w, "graph_histogram.html", data)
}

func handleResolutionGraph(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	bugs, err := loadGraphBugs(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	lastReporting := getNsConfig(ctx, hdr.Namespace).lastActiveReporting()
	data := &uiResolutionPage{
		Header: hdr,
		Graph:  createResolutionGraph(timeNow(ctx), bugs, lastReporting),
	}
	return serveTemplate(w, "graph_resolution.html", data)
}

const resolutionRateMonths = 6

// createResolutionGraph computes the percentage of bugs addressed within X months (X=1..resolutionRateMonths).
// To prevent population shift in the denominator across horizons (which would cause the cumulative
// resolution curve to decrease), we evaluate a fixed mature cohort of bugs reported between 2 years
// and resolutionRateMonths ago (T_reported in [now - 2 years, now - resolutionRateMonths]).
// This guarantees every bug in the cohort has at least resolutionRateMonths of observation history, producing a
// constant denominator and a strictly non-decreasing resolution curve across all months.
func createResolutionGraph(now time.Time, bugs []*Bug, lastReporting int) *uiGraph {
	twoYearsAgo := now.AddDate(-2, 0, 0)
	cohortCutoff := now.AddDate(0, -resolutionRateMonths, 0)
	var columns []uiGraphColumn

	for month := 1; month <= resolutionRateMonths; month++ {
		total := 0
		fixed := 0

		for _, bug := range bugs {
			// Duplicate bugs are resolved via their canonical bug (which is counted separately).
			if bug.Status == BugStatusDup {
				continue
			}
			repDate := bugReportedDate(bug, lastReporting)
			// Restrict dataset to bugs in the fixed mature cohort (reported between 2 years ago and resolutionRateMonths ago).
			if repDate.Before(twoYearsAgo) || repDate.After(cohortCutoff) {
				continue
			}
			// Auto-obsoleted bugs (where syzbot stopped hitting the bug after 90 days without a fix)
			// remain in the denominator for all mature horizons as unfixed bugs. They are not skipped or dropped,
			// which prevents an artificial 90-day resolution rate spike.
			// Manually obsoleted bugs are treated as resolved at their closure date via bugFixDate.
			total++
			fixDate := bugFixDate(bug)
			if !fixDate.IsZero() && !fixDate.After(repDate.AddDate(0, month, 0)) {
				fixed++
			}
		}

		var pct float32
		if total > 0 {
			pct = float32(fixed) / float32(total) * 100
		}

		columns = append(columns, uiGraphColumn{
			Hint:       fmt.Sprintf("%dm", month),
			Annotation: pct,
			Vals:       []uiGraphValue{{Val: pct, Hint: fmt.Sprintf("%d/%d bugs (%.1f%%)", fixed, total, pct)}},
		})
	}

	return &uiGraph{
		Headers: []uiGraphHeader{{Name: "% Addressed Within X Months", Color: "#26ba1c"}},
		Columns: columns,
	}
}

// bugReportedDate determines the timestamp when a bug became publicly reported.
// Bugs that reached the final reporting stage (e.g., LKML) use that stage's exact report timestamp.
// Bugs fixed or closed before reaching the final stage use their initial report timestamp or first seen time.
func bugReportedDate(bug *Bug, lastReporting int) time.Time {
	if len(bug.Reporting) > lastReporting && !bug.Reporting[lastReporting].Reported.IsZero() {
		return bug.Reporting[lastReporting].Reported
	}
	for _, r := range bug.Reporting {
		if !r.Reported.IsZero() {
			return r.Reported
		}
	}
	return bug.FirstTime
}

// bugFixDate determines the true resolution timestamp for a bug.
// Developers often fix bugs in git commits before syzbot detects and closes the bug in Datastore.
// We prefer the earliest commit date from CommitInfo to measure real-world time-to-fix accurately,
// falling back to Bug.Closed or Bug.FixTime if commit metadata is unavailable.
func bugFixDate(bug *Bug) time.Time {
	var earliestCommit time.Time
	for _, com := range bug.CommitInfo {
		if !com.Date.IsZero() && (earliestCommit.IsZero() || com.Date.Before(earliestCommit)) {
			earliestCommit = com.Date
		}
	}
	if !earliestCommit.IsZero() {
		return earliestCommit
	}
	if bug.Status == BugStatusFixed && !bug.Closed.IsZero() {
		return bug.Closed
	}
	if !bug.FixTime.IsZero() {
		return bug.FixTime
	}
	// If a maintainer manually invalidates/obsoletes a bug, consider manual obsoletion
	// as resolution (resolved/addressed), using the bug closure timestamp as the resolution date.
	if bug.Status == BugStatusInvalid {
		rep := lastReportedReporting(bug)
		if rep != nil && !rep.Auto && !bug.Closed.IsZero() {
			return bug.Closed
		}
	}
	return time.Time{}
}

func loadGraphBugs(ctx context.Context, ns string) ([]*Bug, error) {
	filter := func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", ns)
	}
	bugs, _, err := loadAllBugs(ctx, filter)
	if err != nil {
		return nil, err
	}
	n := 0
	fixes := make(map[string]bool)
	lastReporting := getNsConfig(ctx, ns).lastActiveReporting()
	for _, bug := range bugs {
		if bug.Reporting[lastReporting].Reported.IsZero() {
			// Bugs with fixing commits are considered public (see Bug.sanitizeAccess).
			if bug.Status == BugStatusOpen && len(bug.Commits) == 0 {
				// These bugs are not released yet.
				continue
			}
			bugReporting := lastReportedReporting(bug)
			if bugReporting == nil || bugReporting.Auto && bug.Status == BugStatusInvalid {
				// These bugs were auto-obsoleted before getting released.
				continue
			}
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

// loadStableGraphBugs is similar to loadGraphBugs, but it does not remove duplicates and auto-invalidated bugs.
// This ensures that the set of bugs does not change much over time.
func loadStableGraphBugs(ctx context.Context, ns string) ([]*Bug, error) {
	bugs, _, err := loadNamespaceBugs(ctx, ns)
	if err != nil {
		return nil, err
	}
	return filterStableGraphBugs(ctx, bugs, ns), nil
}

func filterStableGraphBugs(ctx context.Context, bugs []*Bug, ns string) []*Bug {
	var res []*Bug
	lastReporting := getNsConfig(ctx, ns).lastActiveReporting()
	for _, bug := range bugs {
		if isStableBug(ctx, bug, lastReporting) {
			res = append(res, bug)
		}
	}
	return res
}

func isStableBug(ctx context.Context, bug *Bug, lastReporting int) bool {
	// Bugs with fixing commits are considered public (see Bug.sanitizeAccess).
	if !bug.Reporting[lastReporting].Reported.IsZero() ||
		bug.Status == BugStatusFixed || len(bug.Commits) != 0 {
		return true
	}
	// Invalid/dup not in the final reporting.
	if bug.Status != BugStatusOpen {
		return false
	}
	// The bug is still open, but not in the final reporting.
	// Check if it's delayed from reaching the final reporting only by embargo.
	for i := range bug.Reporting {
		if i == lastReporting {
			return true
		}
		if !bug.Reporting[i].Closed.IsZero() {
			continue
		}
		reporting := getNsConfig(ctx, bug.Namespace).ReportingByName(bug.Reporting[i].Name)
		if !bug.Reporting[i].Reported.IsZero() && reporting.Embargo != 0 {
			continue
		}
		if reporting.Filter(bug) == FilterSkip {
			continue
		}
		return false
	}
	return false
}

func createBugsGraph(ctx context.Context, bugs []*Bug) *uiGraph {
	type BugStats struct {
		Opened        int
		Fixed         int
		Closed        int
		TotalReported int
		TotalOpen     int
		TotalFixed    int
		TotalClosed   int
	}
	const timeWeek = 30 * 24 * time.Hour
	now := timeNow(ctx)
	m := make(map[int]*BugStats)
	maxWeek := 0
	bugStatsFor := func(t time.Time) *BugStats {
		week := max(0, int(now.Sub(t)/(30*24*time.Hour)))
		maxWeek = max(maxWeek, week)
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
			if bug.Status == BugStatusFixed {
				bugStatsFor(bug.Closed).Fixed++
			}
			bugStatsFor(bug.Closed).Closed++
		} else if len(bug.Commits) != 0 {
			bugStatsFor(now).Fixed++
			bugStatsFor(now).Closed++
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
		bs.TotalClosed = prev.TotalClosed + bs.Closed
		bs.TotalOpen = bs.TotalReported - bs.TotalClosed
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
		Headers: []uiGraphHeader{{Name: "open bugs"}, {Name: "total reported"}, {Name: "total fixed"}},
		Columns: columns,
	}
}

func createFoundBugs(ctx context.Context, bugs []*Bug) *uiGraph {
	const projected = "projected"
	// This is linux-specific at the moment, potentially can move to pkg/report/crash
	// and extend to other OSes.
	types := []struct {
		name  string
		color string
		pred  crash.TypeGroupPred
	}{
		{"KASAN", "Red", crash.Type.IsKASAN},
		{"KMSAN", "Gold", crash.Type.IsKMSAN},
		{"KCSAN", "Fuchsia", crash.Type.IsKCSAN},
		{"mem safety", "OrangeRed", crash.Type.IsMemSafety},
		{"mem leak", "MediumSeaGreen", crash.Type.IsMemoryLeak},
		{"locking", "DodgerBlue", crash.Type.IsLockingBug},
		{"hangs/stalls", "LightSalmon", crash.Type.IsHang},
		// This must be at the end, otherwise "BUG:" will match other error types.
		{"DoS", "Violet", crash.Type.IsDoS},
		{"other", "Gray", func(crash.Type) bool { return true }},
		{projected, "LightGray", nil},
	}
	var sorted []time.Time
	months := make(map[time.Time]map[string]int)
	for _, bug := range bugs {
		for _, typ := range types {
			if !typ.pred(crash.TitleToType(bug.Title)) {
				continue
			}
			t := bug.FirstTime
			m := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
			if months[m] == nil {
				months[m] = make(map[string]int)
				sorted = append(sorted, m)
			}
			months[m][typ.name]++
			break
		}
	}
	slices.SortFunc(sorted, func(a, b time.Time) int {
		return a.Compare(b)
	})
	now := timeNow(ctx)
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if m := months[thisMonth]; m != nil {
		total := 0
		for _, c := range m {
			total += c
		}
		nextMonth := thisMonth.AddDate(0, 1, 0)
		m[projected] = int(float64(total) / float64(now.Sub(thisMonth)) * float64(nextMonth.Sub(now)))
	}
	var headers []uiGraphHeader
	for _, typ := range types {
		headers = append(headers, uiGraphHeader{Name: typ.name, Color: typ.color})
	}
	var columns []uiGraphColumn
	for _, month := range sorted {
		col := uiGraphColumn{Hint: month.Format("Jan-06")}
		stats := months[month]
		for _, typ := range types {
			val := float32(stats[typ.name])
			col.Vals = append(col.Vals, uiGraphValue{Val: val})
			col.Annotation += val
		}
		columns = append(columns, col)
	}
	return &uiGraph{
		Headers: headers,
		Columns: columns,
	}
}

func createBugLifetimes(ctx context.Context, bugs []*Bug, causeBisects map[string]*Job) []uiBugLifetime {
	var res []uiBugLifetime
	for i, bug := range bugs {
		if bug.Status >= BugStatusInvalid {
			continue
		}
		reported := bug.FirstTime
		// Find reporting date to the last reporting stage (where it was reported),
		// it's a more meaningful date b/c the bug could not be fixed before that.
		for _, reporting := range bug.Reporting {
			if reported.Before(reporting.Reported) {
				reported = reporting.Reported
			}
		}
		ui := uiBugLifetime{}
		fixed := bug.FixTime
		if fixed.IsZero() || bug.Status == BugStatusFixed && bug.Closed.Before(fixed) {
			fixed = bug.Closed
		}
		fixedDaysAgo := max(0, float32(fixed.Sub(reported))/float32(24*time.Hour))
		if !fixed.IsZero() {
			// We use fixed date as the X coordiate (date) for fixed bugs to show
			// how lifetime of bugs fixed at the given date (e.g. lately).
			ui.Reported = fixed
			if fixedDaysAgo > 365 {
				// Cap Y coordinate to 365 to make Y coordinates with the first year
				// distinguishable in presence of very large Y coordinates
				// (e.g. if something was fixed/introduced in 5 years).
				// Add small jitter to min/max values to make close dots distinguishable.
				ui.Fixed1y = 365 + float32(i%7)
			} else {
				ui.Fixed = max(0.2*(1+float32(i%5)), fixedDaysAgo)
			}
		} else {
			ui.Reported = reported
			ui.NotFixed = 400 - float32(i%10)
		}
		res = append(res, ui)
		ui = uiBugLifetime{
			Reported: reported,
		}
		if job := causeBisects[bug.keyHash(ctx)]; job != nil {
			days := float32(job.Commits[0].Date.Sub(ui.Reported)) / float32(24*time.Hour)
			if days < -365 {
				ui.Introduced1y = -365 - float32(i%7)
			} else {
				ui.Introduced = min(-0.2*(1+float32(i%5)), days)
			}
		}
		res = append(res, ui)
	}
	return res
}

func handleGraphFuzzing(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	r.ParseForm()

	allManagers, err := managerList(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	managers, err := createCheckBox(r, "Instances", allManagers)
	if err != nil {
		return err
	}
	metrics, err := createCheckBox(r, "Metrics", []string{
		"MaxCorpus", "MaxCover", "MaxPCs", "TotalFuzzingTime",
		"TotalCrashes", "CrashTypes", "SuppressedCrashes", "TotalExecs",
		"ExecsPerSec", "TriagedPCs", "TriagedCoverage"})
	if err != nil {
		return err
	}
	data := &uiManagersPage{
		Header:   hdr,
		Managers: managers,
		Metrics:  metrics,
		Months:   createSlider(r, "Months", 1, 36),
	}
	data.Graph, err = createManagersGraph(ctx, hdr.Namespace, data.Managers.vals, data.Metrics.vals, data.Months.Val*30)
	if err != nil {
		return err
	}
	return serveTemplate(w, "graph_fuzzing.html", data)
}

func createManagersGraph(ctx context.Context, ns string, selManagers, selMetrics []string, days int) (*uiGraph, error) {
	graph := &uiGraph{}
	for _, mgr := range selManagers {
		for _, metric := range selMetrics {
			graph.Headers = append(graph.Headers, uiGraphHeader{Name: mgr + "-" + metric})
		}
	}
	now := timeNow(ctx)
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
		parentKey := mgrKey(ctx, ns, mgr)
		var stats []*ManagerStats
		_, err := db.NewQuery("ManagerStats").
			Ancestor(parentKey).
			GetAll(ctx, &stats)
		if err != nil {
			return nil, err
		}
		for _, stat := range stats {
			dayIndex := days - int(now.Sub(dateTime(stat.Date))/day)
			if dayIndex < 0 || dayIndex > days {
				continue
			}
			for metricIndex, metric := range selMetrics {
				val, canBeZero := extractMetric(stat, metric)
				graph.Columns[dayIndex].Vals[mgrIndex*len(selMetrics)+metricIndex] = uiGraphValue{
					Val:    float32(val),
					IsNull: !canBeZero && val == 0,
					Hint:   fmt.Sprintf("%.2f", val),
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
			maxVal := float32(1)
			for col := range graph.Columns {
				for mgrIndex := range selManagers {
					item := graph.Columns[col].Vals[mgrIndex*len(selMetrics)+metricIndex]
					if item.IsNull {
						continue
					}
					maxVal = max(maxVal, item.Val)
				}
			}
			for col := range graph.Columns {
				for mgrIndex := range selManagers {
					graph.Columns[col].Vals[mgrIndex*len(selMetrics)+metricIndex].Val /= maxVal * 100
				}
			}
		}
	}
	return graph, nil
}

func extractMetric(stat *ManagerStats, metric string) (val float64, canBeZero bool) {
	switch metric {
	case "MaxCorpus":
		return float64(stat.MaxCorpus), false
	case "MaxCover":
		return float64(stat.MaxCover), false
	case "MaxPCs":
		return float64(stat.MaxPCs), false
	case "TotalFuzzingTime":
		return float64(stat.TotalFuzzingTime), true
	case "TotalCrashes":
		return float64(stat.TotalCrashes), true
	case "CrashTypes":
		return float64(stat.CrashTypes), true
	case "SuppressedCrashes":
		return float64(stat.SuppressedCrashes), true
	case "TotalExecs":
		return float64(stat.TotalExecs), true
	case "ExecsPerSec":
		timeSec := float64(stat.TotalFuzzingTime) / 1e9
		if timeSec == 0 {
			return 0, true
		}
		return float64(stat.TotalExecs) / timeSec, true
	case "TriagedCoverage":
		return float64(stat.TriagedCoverage), false
	case "TriagedPCs":
		return float64(stat.TriagedPCs), false
	default:
		panic(fmt.Sprintf("unknown metric %q", metric))
	}
}

// createCheckBox additionally validates r.Form data and returns 400 error in case of mismatch.
func createCheckBox(r *http.Request, caption string, values []string) (*uiCheckbox, error) {
	// TODO: turn this into proper ID that can be used in HTML.
	id := caption
	for _, formVal := range r.Form[id] {
		if !stringInList(values, formVal) {
			return nil, ErrClientBadRequest
		}
	}
	ui := &uiCheckbox{
		ID:      id,
		Caption: caption,
		vals:    r.Form[id],
	}
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
	return ui, nil
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

func createMultiInput(r *http.Request, id, caption string) *uiMultiInput {
	filteredValues := []string{}
	for _, val := range r.Form[id] {
		if val == "" {
			continue
		}
		filteredValues = append(filteredValues, val)
	}
	return &uiMultiInput{
		ID:      id,
		Caption: caption,
		Vals:    filteredValues,
	}
}

func handleGraphCrashes(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	r.ParseForm()

	data := &uiCrashesPage{
		Header:      hdr,
		Regexps:     createMultiInput(r, "regexp", "Regexps"),
		GraphMonths: createSlider(r, "Months", 1, 36),
		TableDays:   createSlider(r, "Days", 1, 30),
	}

	bugs, _, err := loadAllBugs(ctx, func(query *db.Query) *db.Query {
		return query.Filter("Namespace=", hdr.Namespace)
	})
	if err != nil {
		return err
	}
	accessLevel := accessLevel(ctx, r)
	nbugs := 0
	for _, bug := range bugs {
		if accessLevel < bug.sanitizeAccess(ctx, accessLevel) {
			continue
		}
		bugs[nbugs] = bug
		nbugs++
	}
	bugs = bugs[:nbugs]
	if len(data.Regexps.Vals) == 0 {
		// If no data is passed, then at least show the graph for important crash types.
		data.Regexps.Vals = []string{"^KASAN", "^KMSAN", "^KCSAN", "^SYZFAIL"}
	}
	if r.Form["show-graph"] != nil {
		data.Graph, err = createCrashesGraph(ctx, hdr.Namespace, data.Regexps.Vals, data.GraphMonths.Val*30, bugs)
		if err != nil {
			return err
		}
	} else {
		data.Table = createCrashesTable(ctx, hdr.Namespace, data.TableDays.Val, bugs)
	}
	return serveTemplate(w, "graph_crashes.html", data)
}

func createCrashesTable(ctx context.Context, ns string, days int, bugs []*Bug) *uiCrashPageTable {
	const dayDuration = 24 * time.Hour
	startDay := timeNow(ctx).Add(time.Duration(-days+1) * dayDuration)
	table := &uiCrashPageTable{
		Title: fmt.Sprintf("Top crashers of the last %d day(s)", days),
	}
	totalCount := 0
	for _, bug := range bugs {
		count := 0
		for _, s := range bug.dailyStatsTail(startDay) {
			count += s.CrashCount
		}
		if count == 0 {
			continue
		}
		totalCount += count
		titleRegexp := regexp.QuoteMeta(bug.Title)
		table.Rows = append(table.Rows, &uiCrashSummary{
			Title:     bug.Title,
			Link:      bugLink(bug.keyHash(ctx)),
			GraphLink: "?show-graph=1&Months=1&regexp=" + url.QueryEscape(titleRegexp),
			Count:     count,
		})
	}
	for id := range table.Rows {
		table.Rows[id].Share = float32(table.Rows[id].Count) / float32(totalCount) * 100.0
	}
	// Order by descending crash count.
	slices.SortFunc(table.Rows, func(a, b *uiCrashSummary) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return cmp.Compare(a.Title, b.Title)
	})
	return table
}

func createCrashesGraph(ctx context.Context, ns string, regexps []string, days int, bugs []*Bug) (*uiGraph, error) {
	const dayDuration = 24 * time.Hour
	graph := &uiGraph{}
	for _, re := range regexps {
		graph.Headers = append(graph.Headers, uiGraphHeader{Name: re})
	}
	startDay := timeNow(ctx).Add(time.Duration(-days) * dayDuration)
	// Step 1: fill the whole table with empty values.
	dateToIdx := make(map[int]int)
	for date := 0; date <= days; date++ {
		day := startDay.Add(time.Duration(date) * dayDuration)
		dateToIdx[timeDate(day)] = date
		col := uiGraphColumn{Hint: day.Format("02-01-2006")}
		for range regexps {
			col.Vals = append(col.Vals, uiGraphValue{Hint: "-"})
		}
		graph.Columns = append(graph.Columns, col)
	}
	// Step 2: fill in crash counts.
	totalCounts := make(map[int]int)
	for _, bug := range bugs {
		for _, stat := range bug.dailyStatsTail(startDay) {
			pos, ok := dateToIdx[stat.Date]
			if !ok {
				continue
			}
			totalCounts[pos] += stat.CrashCount
		}
	}
	for regexpID, val := range regexps {
		r, err := regexp.Compile(val)
		if err != nil {
			return nil, err
		}
		for _, bug := range bugs {
			if !r.MatchString(bug.Title) {
				continue
			}
			for _, stat := range bug.DailyStats {
				pos, ok := dateToIdx[stat.Date]
				if !ok {
					continue
				}
				graph.Columns[pos].Vals[regexpID].Val += float32(stat.CrashCount)
			}
		}
	}
	// Step 3: convert abs values to percents.
	for date := 0; date <= days; date++ {
		count := totalCounts[date]
		if count == 0 {
			continue
		}
		for id := range graph.Columns[date].Vals {
			value := &graph.Columns[date].Vals[id]
			abs := value.Val
			value.Val = abs / float32(count) * 100.0
			value.Hint = fmt.Sprintf("%.1f%% (%.0f)", value.Val, abs)
		}
	}
	return graph, nil
}
