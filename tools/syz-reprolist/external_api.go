// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/syzkaller/dashboard/api"
)

func reproIDFromURL(url string) string {
	parts := strings.Split(url, "&")
	if len(parts) != 2 {
		log.Panicf("can't split %s in two parts by ?", url)
	}
	parts = strings.Split(parts[1], "=")
	if len(parts) != 2 {
		log.Panicf("can't split %s in two parts by =", url)
	}
	return parts[1]
}

func getBugList(jsonBugs []byte) ([]string, error) {
	var bl api.BugGroup
	if err := json.Unmarshal(jsonBugs, &bl); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}
	if bl.Version != 1 {
		return nil, fmt.Errorf("unsupported export version %d", bl.Version)
	}
	res := []string{}
	for _, b := range bl.Bugs {
		res = append(res, b.Link)
	}
	return res, nil
}

func makeBugDetails(jsonDetails []byte) (*api.Bug, error) {
	var bd api.Bug
	if err := json.Unmarshal(jsonDetails, &bd); err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}
	if bd.Version != 1 {
		return nil, fmt.Errorf("unsupported export version %d", bd.Version)
	}
	return &bd, nil
}
