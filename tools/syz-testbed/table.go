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
	Value     float64
	Sample    *stats.Sample
	ValueDiff *float64
	PValue    *float64
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
