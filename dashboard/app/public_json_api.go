// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "encoding/json"

// publicApiBugDescription is used to serve the /bug HTTP requests
// and provide JSON description of the BUG. Backward compatible.
type publicAPIBugDescription struct {
	Version int    `json:"version"`
	Title   string `json:"title,omitempty"`
	// links to the discussions
	Discussions []string                    `json:"discussions,omitempty"`
	Crashes     []publicAPICrashDescription `json:"crashes,omitempty"`
}

type publicAPICrashDescription struct {
	SyzReproducer       string `json:"syz-reproducer,omitempty"`
	CReproducer         string `json:"c-reproducer,omitempty"`
	KernelConfig        string `json:"kernel-config,omitempty"`
	KernelSourceGit     string `json:"kernel-source-git,omitempty"`
	KernelSourceCommit  string `json:"kernel-source-commit,omitempty"`
	SyzkallerGit        string `json:"syzkaller-git,omitempty"`
	SyzkallerCommit     string `json:"syzkaller-commit,omitempty"`
	CompilerDescription string `json:"compiler-description,omitempty"`
	Architecture        string `json:"architecture,omitempty"`
}

func getExtAPIDescrForBugPage(bugPage *uiBugPage) *publicAPIBugDescription {
	crash := bugPage.Crashes.Crashes[0]
	return &publicAPIBugDescription{
		Version: 1,
		Title:   bugPage.Bug.Title,
		Discussions: func() []string {
			if bugPage.Bug.ExternalLink == "" {
				return nil
			}
			return []string{bugPage.Bug.ExternalLink}
		}(),
		Crashes: []publicAPICrashDescription{{
			SyzReproducer:      crash.ReproSyzLink,
			CReproducer:        crash.ReproCLink,
			KernelConfig:       crash.KernelConfigLink,
			KernelSourceGit:    crash.KernelCommitLink,
			KernelSourceCommit: crash.KernelCommit,
			SyzkallerGit:       crash.SyzkallerCommitLink,
			SyzkallerCommit:    crash.SyzkallerCommit,
			// TODO: add the CompilerDescription
			// TODO: add the Architecture
		}},
	}
}

func GetJSONDescrFor(page interface{}) ([]byte, error) {
	var res interface{}
	switch i := page.(type) {
	case *uiBugPage:
		res = getExtAPIDescrForBugPage(i)
	default:
		return nil, ErrClientNotFound
	}
	return json.MarshalIndent(res, "", "\t")
}
