// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"cloud.google.com/go/civil"
)

type TimePeriod struct {
	DateTo civil.Date
	Days   int
}

// DatesFromTo returns the closed range [fromDate, toDate].
func (tp *TimePeriod) DatesFromTo() (civil.Date, civil.Date) {
	return tp.DateTo.AddDays(-tp.Days + 1), tp.DateTo
}

func MakeTimePeriod(targetDate civil.Date, periodType string) (TimePeriod, error) {
	pOps, err := PeriodOps(periodType)
	if err != nil {
		return TimePeriod{}, err
	}
	tp := TimePeriod{DateTo: targetDate, Days: pOps.PointedPeriodDays(targetDate)}
	if !pOps.IsValidPeriod(tp) {
		return TimePeriod{}, fmt.Errorf("date %s doesn't point the period(%s) end", targetDate.String(), periodType)
	}
	return tp, nil
}

const (
	DayPeriod     = "day"
	MonthPeriod   = "month"
	QuarterPeriod = "quarter"
)

var errUnknownTimePeriodType = errors.New("unknown time period type")

func MinMaxDays(periodType string) (int, int, error) {
	switch periodType {
	case DayPeriod:
		return 1, 1, nil
	case MonthPeriod:
		return 28, 31, nil
	case QuarterPeriod:
		return 31 + 28 + 31, 31 + 30 + 31, nil
	default:
		return 0, 0, errUnknownTimePeriodType
	}
}

func PeriodOps(periodType string) (periodOps, error) {
	switch periodType {
	case DayPeriod:
		return &DayPeriodOps{}, nil
	case MonthPeriod:
		return &MonthPeriodOps{}, nil
	case QuarterPeriod:
		return &QuarterPeriodOps{}, nil
	default:
		return nil, errUnknownTimePeriodType
	}
}

type periodOps interface {
	IsValidPeriod(p TimePeriod) bool
	lastPeriodDate(d civil.Date) civil.Date
	PointedPeriodDays(d civil.Date) int
}

func GenNPeriodsTill(n int, d civil.Date, po periodOps) []TimePeriod {
	var res []TimePeriod
	for i := 0; i < n; i++ {
		d = po.lastPeriodDate(d)
		res = append(res, TimePeriod{DateTo: d, Days: po.PointedPeriodDays(d)})
		d = d.AddDays(-po.PointedPeriodDays(d))
	}
	slices.Reverse(res)
	return res
}

type DayPeriodOps struct{}

func (dpo *DayPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	return d
}

func (dpo *DayPeriodOps) IsValidPeriod(p TimePeriod) bool {
	return p.Days == 1
}

func (dpo *DayPeriodOps) PointedPeriodDays(d civil.Date) int {
	return 1
}

type MonthPeriodOps struct{}

func (m *MonthPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	d.Day = 1
	d = d.AddDays(32)
	d.Day = 1
	return d.AddDays(-1)
}

func (m *MonthPeriodOps) IsValidPeriod(p TimePeriod) bool {
	lmd := m.lastPeriodDate(p.DateTo)
	return lmd == p.DateTo && p.Days == lmd.Day
}

func (m *MonthPeriodOps) PointedPeriodDays(d civil.Date) int {
	return m.lastPeriodDate(d).Day
}

type QuarterPeriodOps struct{}

func (q *QuarterPeriodOps) IsValidPeriod(p TimePeriod) bool {
	lmd := q.lastPeriodDate(p.DateTo)
	return lmd == p.DateTo && p.Days == q.PointedPeriodDays(lmd)
}

func (q *QuarterPeriodOps) lastPeriodDate(d civil.Date) civil.Date {
	d.Month = ((d.Month-1)/3)*3 + 3
	d.Day = 1
	return (&MonthPeriodOps{}).lastPeriodDate(d)
}

func (q *QuarterPeriodOps) PointedPeriodDays(d civil.Date) int {
	d = q.lastPeriodDate(d)
	d.Day = 1
	res := 0
	for i := 0; i < 3; i++ {
		res += (&MonthPeriodOps{}).PointedPeriodDays(d)
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
		if !ops.IsValidPeriod(period) {
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
			TimePeriod{DateTo: periodEndDate, Days: ops.PointedPeriodDays(periodEndDate)})
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
