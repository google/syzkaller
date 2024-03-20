// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"encoding/json"
	"fmt"
	"io"
)

// CIDetails fields will be added to every CSV line.
type CIDetails struct {
	Version        int    `json:"version"`
	Timestamp      string `json:"timestamp"`
	FuzzingMinutes int    `json:"fuzzing_minutes"`
	Arch           string `json:"arch"`
	BuildID        string `json:"build_id"`
	Manager        string `json:"manager"`
	KernelRepo     string `json:"kernel_repo"`
	KernelBranch   string `json:"kernel_branch"`
	KernelCommit   string `json:"kernel_commit"`
}

type dbCoverageRecord struct {
	CIDetails
	CoverageInfo
}

func writeJSLine(w io.Writer, covInfo dbCoverageRecord) error {
	bs, err := json.Marshal(covInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal covInfo: %w", err)
	}
	bs = append(bs, '\n')
	if _, err = w.Write(bs); err != nil {
		return fmt.Errorf("failed to write js data: %w", err)
	}
	return nil
}

func WriteCIJSONLine(w io.Writer, managerCover CoverageInfo, ciDetails CIDetails) error {
	dbLine := dbCoverageRecord{
		CIDetails:    ciDetails,
		CoverageInfo: managerCover,
	}
	if err := writeJSLine(w, dbLine); err != nil {
		return fmt.Errorf("failed to serialize func line: %w", err)
	}
	return nil
}
