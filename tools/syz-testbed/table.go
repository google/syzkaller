// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/google/syzkaller/pkg/stats"
)

type Cell = interface{}

// All tables that syz-testbed generates have named columns and rows.
// Table type simplifies generation and processing of such tables.
type Table struct {
	TopLeftHeader string
	ColumnHeaders []string
	Cells         map[string]map[string]Cell
}

type ValueCell struct {
	Value         float64
	Sample        *stats.Sample
	PercentChange *float64
	PValue        *float64
}

type RatioCell struct {
	TrueCount  int
	TotalCount int
}

type BoolCell struct {
	Value bool
}

func NewValueCell(sample *stats.Sample) *ValueCell {
	return &ValueCell{Value: sample.Median(), Sample: sample}
}

func (c *ValueCell) String() string {
	const fractionCutoff = 100
	if math.Abs(c.Value) < fractionCutoff {
		return fmt.Sprintf("%.1f", c.Value)
	}
	return fmt.Sprintf("%.0f", math.Round(c.Value))
}

func NewRatioCell(trueCount, totalCount int) *RatioCell {
	return &RatioCell{trueCount, totalCount}
}

func (c *RatioCell) Float64() float64 {
	if c.TotalCount == 0 {
		return 0
	}
	return float64(c.TrueCount) / float64(c.TotalCount)
}

func (c *RatioCell) String() string {
	return fmt.Sprintf("%.1f%% (%d/%d)", c.Float64()*100.0, c.TrueCount, c.TotalCount)
}

func NewBoolCell(value bool) *BoolCell {
	return &BoolCell{
		Value: value,
	}
}

func (c *BoolCell) String() string {
	if c.Value {
		return "YES"
	}
	return "NO"
}

func NewTable(topLeft string, columns ...string) *Table {
	return &Table{
		TopLeftHeader: topLeft,
		ColumnHeaders: columns,
	}
}

func (t *Table) Get(row, column string) Cell {
	if t.Cells == nil {
		return nil
	}
	rowMap := t.Cells[row]
	if rowMap == nil {
		return nil
	}
	return rowMap[column]
}

func (t *Table) Set(row, column string, value Cell) {
	if t.Cells == nil {
		t.Cells = make(map[string]map[string]Cell)
	}
	rowMap, ok := t.Cells[row]
	if !ok {
		rowMap = make(map[string]Cell)
		t.Cells[row] = rowMap
	}
	rowMap[column] = value
}

func (t *Table) AddColumn(column string) {
	t.ColumnHeaders = append(t.ColumnHeaders, column)
}

func (t *Table) AddRow(row string, cells ...Cell) {
	if len(cells) != len(t.ColumnHeaders) {
		panic("AddRow: the length of the row does not equal the number of columns")
	}
	for i, col := range t.ColumnHeaders {
		t.Set(row, col, cells[i])
	}
}

func (t *Table) SortedRows() []string {
	rows := []string{}
	for key := range t.Cells {
		rows = append(rows, key)
	}
	sort.Strings(rows)
	return rows
}

func (t *Table) ToStrings() [][]string {
	table := [][]string{}
	headers := append([]string{t.TopLeftHeader}, t.ColumnHeaders...)
	table = append(table, headers)
	if t.Cells != nil {
		rowHeaders := t.SortedRows()
		for _, row := range rowHeaders {
			tableRow := []string{row}
			for _, column := range t.ColumnHeaders {
				tableRow = append(tableRow, fmt.Sprintf("%s", t.Get(row, column)))
			}
			table = append(table, tableRow)
		}
	}
	return table
}

func (t *Table) SaveAsCsv(fileName string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	return csv.NewWriter(f).WriteAll(t.ToStrings())
}

func (t *Table) SetRelativeValues(baseColumn string) error {
	for rowName, row := range t.Cells {
		baseCell := t.Get(rowName, baseColumn)
		if baseCell == nil {
			return fmt.Errorf("base column %s not found in row %s", baseColumn, rowName)
		}
		baseValueCell, ok := baseCell.(*ValueCell)
		if !ok {
			return fmt.Errorf("base column cell is not a ValueCell, %T", baseCell)
		}
		baseSample := baseValueCell.Sample.RemoveOutliers()
		for column, cell := range row {
			if column == baseColumn {
				continue
			}
			valueCell, ok := cell.(*ValueCell)
			if !ok {
				continue
			}
			if baseValueCell.Value != 0 {
				valueDiff := valueCell.Value - baseValueCell.Value
				valueCell.PercentChange = new(float64)
				*valueCell.PercentChange = valueDiff / baseValueCell.Value * 100
			}

			cellSample := valueCell.Sample.RemoveOutliers()
			pval, err := stats.UTest(baseSample, cellSample)
			if err == nil {
				// Sometimes it fails because there are too few samples.
				valueCell.PValue = new(float64)
				*valueCell.PValue = pval
			}
		}
	}
	return nil
}

func (t *Table) GetFooterValue(column string) Cell {
	nonEmptyCells := 0
	ratioCells := []*RatioCell{}
	boolCells := []*BoolCell{}
	valueCells := []*ValueCell{}
	for rowName := range t.Cells {
		cell := t.Get(rowName, column)
		if cell == nil {
			continue
		}
		nonEmptyCells++

		switch v := cell.(type) {
		case *RatioCell:
			ratioCells = append(ratioCells, v)
		case *BoolCell:
			boolCells = append(boolCells, v)
		case *ValueCell:
			valueCells = append(valueCells, v)
		}
	}
	if nonEmptyCells == 0 {
		return ""
	}
	switch nonEmptyCells {
	case len(ratioCells):
		var sum, count float64
		for _, cell := range ratioCells {
			sum += cell.Float64()
			count++
		}
		return fmt.Sprintf("%.1f%%", sum/count*100.0)
	case len(valueCells):
		var sum, count float64
		for _, cell := range valueCells {
			sum += cell.Value
			count++
		}
		return fmt.Sprintf("%.1f", sum/count)
	case len(boolCells):
		yes := 0
		for _, cell := range boolCells {
			if cell.Value {
				yes++
			}
		}
		return NewRatioCell(yes, len(t.Cells))
	default:
		// Column has mixed type cells, we cannot do anything here.
		return ""
	}
}
