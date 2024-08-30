// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"github.com/stretchr/testify/assert"
)

func TestDayPeriodOps(t *testing.T) {
	ops := &DayPeriodOps{}
	d := civil.Date{Year: 2024, Month: time.February, Day: 20}
	goodPeriod := TimePeriod{DateTo: d, Days: 1}
	badPeriod := TimePeriod{DateTo: d, Days: 2}

	assert.Equal(t, "2024-02-20", ops.lastPeriodDate(d).String())

	assert.True(t, ops.IsValidPeriod(goodPeriod))
	assert.False(t, ops.IsValidPeriod(badPeriod))

	assert.Equal(t, 1, ops.PointedPeriodDays(d))

	assert.Equal(t,
		[]TimePeriod{
			{DateTo: civil.Date{Year: 2024, Month: time.February, Day: 19}, Days: 1},
			{DateTo: civil.Date{Year: 2024, Month: time.February, Day: 20}, Days: 1}},
		GenNPeriodsTill(2, d, ops))
}

func TestMonthPeriodOps(t *testing.T) {
	ops := &MonthPeriodOps{}
	midMonthDate := civil.Date{Year: 2024, Month: time.February, Day: 20}
	goodPeriod := TimePeriod{DateTo: midMonthDate, Days: 29}
	goodPeriod.DateTo.Day = goodPeriod.Days
	badPeriod1 := goodPeriod
	badPeriod1.DateTo.Day--
	badPeriod2 := goodPeriod
	badPeriod2.Days--

	assert.Equal(t, "2024-02-29", ops.lastPeriodDate(midMonthDate).String())

	assert.True(t, ops.IsValidPeriod(goodPeriod))
	assert.False(t, ops.IsValidPeriod(badPeriod1))
	assert.False(t, ops.IsValidPeriod(badPeriod2))

	assert.Equal(t, 29, ops.PointedPeriodDays(midMonthDate))

	assert.Equal(t,
		[]TimePeriod{
			{DateTo: civil.Date{Year: 2024, Month: time.January, Day: 31}, Days: 31},
			{DateTo: civil.Date{Year: 2024, Month: time.February, Day: 29}, Days: 29}},
		GenNPeriodsTill(2, goodPeriod.DateTo, ops))
}

func TestQuarterPeriodOps(t *testing.T) {
	ops := &QuarterPeriodOps{}
	midQuarterDate := civil.Date{Year: 2024, Month: time.February, Day: 20}
	goodPeriod := TimePeriod{DateTo: midQuarterDate, Days: 31 + 29 + 31}
	goodPeriod.DateTo.Month = time.March
	goodPeriod.DateTo.Day = 31
	badPeriod1 := goodPeriod
	badPeriod1.DateTo.Day--
	badPeriod2 := goodPeriod
	badPeriod2.Days--

	assert.Equal(t, "2024-03-31", ops.lastPeriodDate(midQuarterDate).String())

	assert.True(t, ops.IsValidPeriod(goodPeriod))
	assert.False(t, ops.IsValidPeriod(badPeriod1))
	assert.False(t, ops.IsValidPeriod(badPeriod2))

	assert.Equal(t, 31+29+31, ops.PointedPeriodDays(midQuarterDate))

	assert.Equal(t,
		[]TimePeriod{
			{DateTo: civil.Date{Year: 2023, Month: time.December, Day: 31}, Days: 31 + 30 + 31},
			{DateTo: civil.Date{Year: 2024, Month: time.March, Day: 31}, Days: 31 + 29 + 31}},
		GenNPeriodsTill(2, goodPeriod.DateTo, ops))
}

func TestPeriodsToMerge(t *testing.T) {
	sampleDays := []TimePeriod{
		makeTimePeriod("2024-04-01", 1),
		makeTimePeriod("2024-04-02", 1),
		makeTimePeriod("2024-05-03", 1),
		makeTimePeriod("2024-05-04", 1),
		makeTimePeriod("2024-06-05", 1),
		makeTimePeriod("2024-06-06", 1),
	}
	sampleRows := []int64{1, 2, 4, 8, 16, 32}

	tests := []struct {
		name          string
		srcDates      []TimePeriod
		srcRows       []int64
		mergedPeriods []TimePeriod
		mergedRows    []int64
		ops           periodOps
		expected      []TimePeriod
	}{
		{
			name:     "days/all_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-01", 1),
				makeTimePeriod("2024-04-02", 1),
				makeTimePeriod("2024-05-03", 1),
				makeTimePeriod("2024-05-04", 1),
				makeTimePeriod("2024-06-05", 1),
				makeTimePeriod("2024-06-06", 1),
			},
			mergedRows: []int64{1, 2, 4, 8, 16, 32},
			ops:        &DayPeriodOps{},
			expected:   []TimePeriod{},
		},
		{
			name:     "days/some_not_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-01", 1),
				makeTimePeriod("2024-05-03", 1),
				makeTimePeriod("2024-05-04", 1),
				makeTimePeriod("2024-06-06", 1),
			},
			mergedRows: []int64{1, 4, 8, 32},
			ops:        &DayPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-05", 1),
				makeTimePeriod("2024-04-02", 1),
			},
		},
		{
			name:     "days/some_partially_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-01", 1),
				makeTimePeriod("2024-04-02", 1),
				makeTimePeriod("2024-05-03", 1),
				makeTimePeriod("2024-05-04", 1),
				makeTimePeriod("2024-06-05", 1),
				makeTimePeriod("2024-06-06", 1),
			},
			mergedRows: []int64{1, 2, 1, 8, 16, 1},
			ops:        &DayPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-06", 1),
				makeTimePeriod("2024-05-03", 1),
			},
		},
		{
			name:     "months/all_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-30", 30),
				makeTimePeriod("2024-05-31", 31),
				makeTimePeriod("2024-06-30", 30),
			},
			mergedRows: []int64{3, 12, 48},
			ops:        &MonthPeriodOps{},
			expected:   []TimePeriod{},
		},
		{
			name:     "months/some_not_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-30", 30),
				makeTimePeriod("2024-05-31", 31),
			},
			mergedRows: []int64{3, 12},
			ops:        &MonthPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-30", 30),
			},
		},
		{
			name:     "months/some_partially_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-04-30", 30),
				makeTimePeriod("2024-05-31", 31),
				makeTimePeriod("2024-06-30", 30),
			},
			mergedRows: []int64{1, 12, 1},
			ops:        &MonthPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-30", 30),
				makeTimePeriod("2024-04-30", 30),
			},
		},

		{
			name:     "quarter/all_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-06-30", 30+31+30),
			},
			mergedRows: []int64{63},
			ops:        &QuarterPeriodOps{},
			expected:   []TimePeriod{},
		},
		{
			name:          "quarter/not_merged",
			srcDates:      sampleDays,
			srcRows:       sampleRows,
			mergedPeriods: []TimePeriod{},
			mergedRows:    []int64{},
			ops:           &QuarterPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-30", 30+31+30),
			},
		},
		{
			name:     "quarter/partially_merged",
			srcDates: sampleDays,
			srcRows:  sampleRows,
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-06-30", 30+31+30),
			},
			mergedRows: []int64{60},
			ops:        &QuarterPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-30", 30+31+30),
			},
		},
		{
			name:     "quarters/not_all_merged_with_invalid_periods",
			srcDates: append(sampleDays, makeTimePeriod("2024-01-01", 1)),
			srcRows:  append(sampleRows, 128),
			mergedPeriods: []TimePeriod{
				makeTimePeriod("2024-03-31", 31+29+31),
				makeTimePeriod("2024-06-30", 30+31+30),
				makeTimePeriod("2024-01-10", 30),
				makeTimePeriod("2024-01-20", 1),
			},
			mergedRows: []int64{128, 60, 1, 1},
			ops:        &QuarterPeriodOps{},
			expected: []TimePeriod{
				makeTimePeriod("2024-06-30", 30+31+30),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, len(test.srcRows), len(test.srcDates))
			actual := PeriodsToMerge(test.srcDates, test.mergedPeriods, test.srcRows, test.mergedRows, test.ops)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func makeTimePeriod(s string, days int) TimePeriod {
	d, err := civil.ParseDate(s)
	if err != nil {
		panic(err.Error())
	}
	return TimePeriod{DateTo: d, Days: days}
}

func TestAtMostNLatestPeriods(t *testing.T) {
	sampleDays := []TimePeriod{
		makeTimePeriod("2024-04-01", 1),
		makeTimePeriod("2024-04-02", 1),
		makeTimePeriod("2024-05-03", 1),
		makeTimePeriod("2024-05-04", 1),
		makeTimePeriod("2024-06-05", 1),
		makeTimePeriod("2024-06-06", 1),
	}
	assert.Equal(t, []TimePeriod{makeTimePeriod("2024-06-06", 1)}, AtMostNLatestPeriods(sampleDays, 1))
	assert.Equal(t, sampleDays, AtMostNLatestPeriods(sampleDays, 100))
}

func TestMakeTimePeriod(t *testing.T) {
	tp, err := MakeTimePeriod(civil.Date{Year: 2024, Month: time.March, Day: 31}, QuarterPeriod)
	assert.NoError(t, err)
	assert.NotEqual(t, TimePeriod{}, tp)

	tp, err = MakeTimePeriod(civil.Date{Year: 2024, Month: time.March, Day: 30}, QuarterPeriod)
	assert.Error(t, err)
	assert.Equal(t, TimePeriod{}, tp)
}
