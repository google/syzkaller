// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
)

func AddTitlesToStatFile(file string, titles []string) error {
	stat, err := ReadStatFile(file)
	if err != nil {
		return fmt.Errorf("readStatFile: %w", err)
	}
	stat.Add(titles)
	bytes, err := stat.ToBytes()
	if err != nil {
		return err
	}
	return os.WriteFile(file, bytes, 0644)
}

func ReadStatFile(file string) (*TitleStat, error) {
	res := &TitleStat{}
	if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
		return res, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return TitleStatFromBytes(data)
}

func TitleStatFromBytes(data []byte) (*TitleStat, error) {
	var ts TitleStat
	if len(data) == 0 {
		return &ts, nil
	}
	if err := json.Unmarshal(data, &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

type titleStatNodes map[string]*TitleStat

type TitleStat struct {
	Count int
	Nodes titleStatNodes
}

func (ts *TitleStat) Add(reps []string) {
	ts.Count++
	if len(reps) == 0 {
		return
	}
	if ts.Nodes == nil {
		ts.Nodes = make(titleStatNodes)
	}
	if ts.Nodes[reps[0]] == nil {
		ts.Nodes[reps[0]] = &TitleStat{}
	}
	ts.Nodes[reps[0]].Add(reps[1:])
}

func (ts *TitleStat) visit(cb func(int, ...string), titles ...string) {
	if len(ts.Nodes) == 0 {
		cb(ts.Count, titles...)
		return
	}
	for title := range maps.Keys(ts.Nodes) {
		ts.Nodes[title].visit(cb, append(titles, title)...)
	}
}

func (ts *TitleStat) ToBytes() ([]byte, error) {
	return json.MarshalIndent(ts, "", "\t")
}

type TitleFreqRank struct {
	Title string
	Count int
	Total int
	Rank  int
}

func (ts *TitleStat) Explain() []*TitleFreqRank {
	titleCount := map[string]int{}

	ts.visit(func(count int, titles ...string) {
		uniq := map[string]bool{}
		for _, title := range titles {
			uniq[title] = true
		}
		for title := range uniq {
			titleCount[title] += count
		}
	})
	var res []*TitleFreqRank
	for title, count := range titleCount {
		res = append(res, &TitleFreqRank{
			Title: title,
			Count: count,
			Total: ts.Count,
			Rank:  TitlesToImpact(title),
		})
	}
	sort.Slice(res, func(l, r int) bool {
		if res[l].Rank != res[r].Rank {
			return res[l].Rank > res[r].Rank
		}
		lTitle, rTitle := res[l].Title, res[r].Title
		if titleCount[lTitle] != titleCount[rTitle] {
			return titleCount[lTitle] > titleCount[rTitle]
		}
		return lTitle < rTitle
	})
	return res
}

// HigherRankTooltip generates a prioritized list of titles with a rank higher than firstTitle.
func HigherRankTooltip(firstTitle string, titlesInfo []*TitleFreqRank) string {
	baseRank := TitlesToImpact(firstTitle)
	res := ""
	for _, ti := range titlesInfo {
		if ti.Rank <= baseRank {
			continue
		}
		res += fmt.Sprintf("[rank %2v, freq %5.1f%%] %s\n",
			ti.Rank,
			100*float32(ti.Count)/float32(ti.Total),
			ti.Title)
	}
	if res != "" {
		return fmt.Sprintf("[rank %2v,  originally] %s\n%s", baseRank, firstTitle, res)
	}
	return res
}
