// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import "fmt"

// URLGenerator creates URLs for accessing the web dashboard.
type URLGenerator struct {
	baseURL string
}

func NewURLGenerator(baseURL string) *URLGenerator {
	return &URLGenerator{baseURL}
}

func (g *URLGenerator) FindingLog(findingID string) string {
	return fmt.Sprintf("%s/findings/%s/log", g.baseURL, findingID)
}

func (g *URLGenerator) FindingSyzRepro(findingID string) string {
	return fmt.Sprintf("%s/findings/%s/syz_repro", g.baseURL, findingID)
}

func (g *URLGenerator) FindingCRepro(findingID string) string {
	return fmt.Sprintf("%s/findings/%s/c_repro", g.baseURL, findingID)
}

func (g *URLGenerator) Series(seriesID string) string {
	return fmt.Sprintf("%s/series/%s", g.baseURL, seriesID)
}

func (g *URLGenerator) BuildConfig(buildID string) string {
	return fmt.Sprintf("%s/builds/%s/config", g.baseURL, buildID)
}

func (g *URLGenerator) BuildLog(buildID string) string {
	return fmt.Sprintf("%s/builds/%s/log", g.baseURL, buildID)
}
