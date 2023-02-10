// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"regexp"
	"strings"
)

type PathMatcher struct {
	matches []*match
}

type match struct {
	include *regexp.Regexp
	exclude *regexp.Regexp
	object  *Subsystem
}

func MakePathMatcher(list []*Subsystem) *PathMatcher {
	m := &PathMatcher{}
	for _, item := range list {
		m.register(item)
	}
	return m
}

func (p *PathMatcher) register(item *Subsystem) {
	onlyInclude := []string{}
	list := []PathRule{}
	for _, r := range item.PathRules {
		if r.ExcludeRegexp == "" {
			// It's expected that almost everything will go to this branch.
			onlyInclude = append(onlyInclude, r.IncludeRegexp)
		} else {
			list = append(list, r)
		}
	}
	if len(onlyInclude) > 0 {
		list = append(list, PathRule{
			IncludeRegexp: strings.Join(onlyInclude, "|"),
		})
	}
	for _, rule := range list {
		p.matches = append(p.matches, buildMatch(rule, item))
	}
}

func (p *PathMatcher) Match(path string) []*Subsystem {
	ret := []*Subsystem{}
	for _, m := range p.matches {
		if m.exclude != nil && m.exclude.MatchString(path) {
			continue
		}
		if m.include != nil && !m.include.MatchString(path) {
			continue
		}
		ret = append(ret, m.object)
	}
	return ret
}

func buildMatch(rule PathRule, item *Subsystem) *match {
	m := &match{object: item}
	if rule.IncludeRegexp != "" {
		m.include = regexp.MustCompile(rule.IncludeRegexp)
	}
	if rule.ExcludeRegexp != "" {
		m.exclude = regexp.MustCompile(rule.ExcludeRegexp)
	}
	return m
}
