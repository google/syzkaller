// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// package dashboard defines data structures used in dashboard communication
// and provides client interface.
package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Dashboard struct {
	Addr   string
	Client string
	Key    string
}

type Crash struct {
	Tag    string
	Desc   string
	Log    []byte
	Report []byte
}

type Repro struct {
	Crash      Crash
	Reproduced bool
	Opts       string
	Prog       []byte
	CProg      []byte
}

type Patch struct {
	Title string
	Diff  []byte
}

func (dash *Dashboard) ReportCrash(crash *Crash) error {
	return dash.query("add_crash", crash, nil)
}

func (dash *Dashboard) ReportRepro(repro *Repro) error {
	return dash.query("add_repro", repro, nil)
}

func (dash *Dashboard) PollPatches() (string, error) {
	hash := ""
	err := dash.query("poll_patches", nil, &hash)
	return hash, err
}

func (dash *Dashboard) GetPatches() ([]Patch, error) {
	var patches []Patch
	err := dash.query("get_patches", nil, &patches)
	return patches, err
}

func (dash *Dashboard) query(method string, req, reply interface{}) error {
	values := make(url.Values)
	values.Add("client", dash.Client)
	values.Add("key", dash.Key)
	values.Add("method", method)
	var body io.Reader
	if req != nil {
		data, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %v", err)
		}
		body = bytes.NewReader(data)
	}
	resp, err := http.Post(fmt.Sprintf("%v/api?%v", dash.Addr, values.Encode()), "application/json", body)
	if err != nil {
		return fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("request failed with %v: %s", resp.Status, data)
	}
	if reply != nil {
		if err := json.NewDecoder(resp.Body).Decode(reply); err != nil {
			return fmt.Errorf("failed to unmarshal response: %v", err)
		}
	}
	return nil
}
