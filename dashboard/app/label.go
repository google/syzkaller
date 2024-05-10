// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

const (
	EmptyLabel           BugLabelType = ""
	SubsystemLabel       BugLabelType = "subsystems"
	PriorityLabel        BugLabelType = "prio"
	NoRemindersLabel     BugLabelType = "no-reminders"
	OriginLabel          BugLabelType = "origin"
	MissingBackportLabel BugLabelType = "missing-backport"
)

type BugPrio string

const (
	LowPrioBug    BugPrio = "low"
	NormalPrioBug BugPrio = "normal"
	HighPrioBug   BugPrio = "high"
)

type oneOf []string
type subsetOf []string
type trueFalse struct{}

func makeLabelSet(c context.Context, ns string) *labelSet {
	ret := map[BugLabelType]interface{}{
		PriorityLabel: oneOf([]string{
			string(LowPrioBug),
			string(NormalPrioBug),
			string(HighPrioBug),
		}),
		NoRemindersLabel:     trueFalse{},
		MissingBackportLabel: trueFalse{},
	}
	service := getNsConfig(c, ns).Subsystems.Service
	if service != nil {
		names := []string{}
		for _, item := range service.List() {
			names = append(names, item.Name)
		}
		ret[SubsystemLabel] = subsetOf(names)
	}

	originLabels := []string{}
	for _, repo := range getNsConfig(c, ns).Repos {
		if repo.LabelIntroduced != "" {
			originLabels = append(originLabels, repo.LabelIntroduced)
		}
		if repo.LabelReached != "" {
			originLabels = append(originLabels, repo.LabelReached)
		}
	}

	if len(originLabels) > 0 {
		ret[OriginLabel] = subsetOf(originLabels)
	}

	return &labelSet{
		c:      c,
		ns:     ns,
		labels: ret,
	}
}

type labelSet struct {
	c      context.Context
	ns     string
	labels map[BugLabelType]interface{}
}

func (s *labelSet) FindLabel(label BugLabelType) bool {
	_, ok := s.labels[label]
	return ok
}

func (s *labelSet) ValidateValues(label BugLabelType, values []BugLabel) string {
	rules := s.labels[label]
	if rules == nil {
		return ""
	}
	switch v := rules.(type) {
	case oneOf:
		if len(values) != 1 {
			return "You must specify only one of the allowed values"
		}
		if !stringInList([]string(v), values[0].Value) {
			return fmt.Sprintf("%q is not among the allowed values", values[0].Value)
		}
	case subsetOf:
		for _, item := range values {
			if !stringInList([]string(v), item.Value) {
				return fmt.Sprintf("%q is not among the allowed values", item.Value)
			}
		}
	case trueFalse:
		if len(values) != 1 || values[0].Value != "" {
			return "This label does not support any values"
		}
	}
	return ""
}

func (s *labelSet) Help() string {
	var sortedKeys []BugLabelType
	for key := range s.labels {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return string(sortedKeys[i]) < string(sortedKeys[j])
	})

	var help strings.Builder
	for _, key := range sortedKeys {
		if help.Len() > 0 {
			help.WriteString(", ")
		}
		if key == SubsystemLabel {
			help.WriteString(fmt.Sprintf("%s: {.. see below ..}", key))
			continue
		}
		switch v := s.labels[key].(type) {
		case oneOf:
			help.WriteString(string(key))
			help.WriteString(": {")
			list := []string(v)
			for i := range list {
				if i > 0 {
					help.WriteString(", ")
				}
				help.WriteString(list[i])
			}
			help.WriteByte('}')
		case trueFalse:
			help.WriteString(string(key))
		}
	}

	var sb strings.Builder
	writeWrapped(&sb, help.String())
	if _, ok := s.labels[SubsystemLabel]; ok {
		url := subsystemListURL(s.c, s.ns)
		if url != "" {
			sb.WriteString(fmt.Sprintf("\nThe list of subsystems: %s", url))
		}
	}
	return sb.String()
}

func writeWrapped(sb *strings.Builder, str string) {
	const limit = 80
	lineLen := 0
	for _, token := range strings.Fields(str) {
		if lineLen >= limit ||
			lineLen > 0 && lineLen+len(token) >= limit {
			sb.WriteByte('\n')
			lineLen = 0
		}
		if lineLen > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(token)
		lineLen += len(token)
	}
}

func (bug *Bug) HasLabel(label BugLabelType, value string) bool {
	for _, item := range bug.Labels {
		if item.Label == label && item.Value == value {
			return true
		}
	}
	return false
}

func (bug *Bug) LabelValues(label BugLabelType) []BugLabel {
	var ret []BugLabel
	for _, item := range bug.Labels {
		if item.Label == label {
			ret = append(ret, item)
		}
	}
	return ret
}

func (bug *Bug) SetLabels(set *labelSet, values []BugLabel) error {
	var label BugLabelType
	for _, v := range values {
		if label != EmptyLabel && label != v.Label {
			return fmt.Errorf("values of the same label type are expected")
		}
		label = v.Label
	}
	if errStr := set.ValidateValues(label, values); errStr != "" {
		return fmt.Errorf("%s", errStr)
	}
	bug.UnsetLabels(label)
	bug.Labels = append(bug.Labels, values...)
	return nil
}

func (bug *Bug) UnsetLabels(labels ...BugLabelType) map[BugLabelType]struct{} {
	toDelete := map[BugLabelType]struct{}{}
	notFound := map[BugLabelType]struct{}{}
	for _, name := range labels {
		toDelete[name] = struct{}{}
		notFound[name] = struct{}{}
	}
	var newList []BugLabel
	for _, item := range bug.Labels {
		if _, ok := toDelete[item.Label]; ok {
			delete(notFound, item.Label)
			continue
		}
		newList = append(newList, item)
	}
	bug.Labels = newList
	return notFound
}

func (bug *Bug) HasUserLabel(label BugLabelType) bool {
	for _, item := range bug.Labels {
		if item.Label == label && item.SetBy != "" {
			return true
		}
	}
	return false
}

func (bug *Bug) prio() BugPrio {
	for _, label := range bug.LabelValues(PriorityLabel) {
		return BugPrio(label.Value)
	}
	return NormalPrioBug
}

var bugPrioOrder = map[BugPrio]int{
	LowPrioBug:    1,
	NormalPrioBug: 2,
	HighPrioBug:   3,
}

func (bp BugPrio) LessThan(other BugPrio) bool {
	return bugPrioOrder[bp] < bugPrioOrder[other]
}
