// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"sort"

	"cloud.google.com/go/civil"
)

type TimePeriod struct {
	DateTo civil.Date
	Days   int
}

type periodOps interface {
	isValidPeriod(p TimePeriod) bool
	lastPeriodDate(d civil.Date) civil.Date
	pointedPeriodDays(d civil.Date) int
}

type DayPeriodOps struct{}

func (dpo *DayPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	return d
}

func (dpo *DayPeriodOps) isValidPeriod(p TimePeriod) bool {
	return p.Days == 1
}

func (dpo *DayPeriodOps) pointedPeriodDays(d civil.Date) int {
	return 1
}

type MonthPeriodOps struct{}

func (m *MonthPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	d.Day = 1
	d = d.AddDays(32)
	d.Day = 1
	return d.AddDays(-1)
}

func (m *MonthPeriodOps) isValidPeriod(p TimePeriod) bool {
	lmd := m.lastPeriodDate(p.DateTo)
	return lmd == p.DateTo && p.Days == lmd.Day
}

func (m *MonthPeriodOps) pointedPeriodDays(d civil.Date) int {
	return m.lastPeriodDate(d).Day
}

type QuarterPeriodOps struct{}

func (q *QuarterPeriodOps) isValidPeriod(p TimePeriod) bool {
	lmd := q.lastPeriodDate(p.DateTo)
	return lmd == p.DateTo && p.Days == q.pointedPeriodDays(lmd)
}

func (q *QuarterPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	d.Month = ((d.Month-1)/3)*3 + 3
	d.Day = 1
	return (&MonthPeriodOps{}).lastPeriodDate(d)
}

func (q *QuarterPeriodOps) pointedPeriodDays(d civil.Date) int {
	d = q.lastPeriodDate(d)
	d.Day = 1
	res := 0
	for i := 0; i < 3; i++ {
		res += (&MonthPeriodOps{}).pointedPeriodDays(d)
		d.Month--
	}
	return res
}

func PeriodsToMerge(srcDates, mergedPeriods []TimePeriod, srcRows, mergedRows []int64, ops periodOps) []TimePeriod {
	periodRows := map[civil.Date]int64{}
	for i, srcDate := range srcDates {
		periodID := ops.lastPeriodDate(srcDate.DateTo)
		periodRows[periodID] += srcRows[i]
	}
	for i, period := range mergedPeriods {
		if !ops.isValidPeriod(period) {
			continue
		}
		mergerPeriodID := period.DateTo
		if rowsAvailable, ok := periodRows[mergerPeriodID]; ok && rowsAvailable == mergedRows[i] {
			delete(periodRows, mergerPeriodID)
		}
	}
	periods := []TimePeriod{}
	for periodEndDate := range periodRows {
		periods = append(periods,
			TimePeriod{DateTo: periodEndDate, Days: ops.pointedPeriodDays(periodEndDate)})
	}
	sort.Slice(periods, func(i, j int) bool {
		return periods[i].DateTo.After(periods[j].DateTo)
	})
	return periods
}

func AtMostNLatestPeriods(periods []TimePeriod, n int) []TimePeriod {
	sort.Slice(periods, func(i, j int) bool {
		return periods[i].DateTo.After(periods[j].DateTo)
	})
	if len(periods) <= n {
		return periods
	}
	return periods[:n]
}
