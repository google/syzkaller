// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// package dashapi defines data structures used in dashboard communication
// and provides client interface.
package dashapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Dashboard struct {
	Client string
	Addr   string
	Key    string
}

func New(client, addr, key string) *Dashboard {
	return &Dashboard{
		Client: client,
		Addr:   addr,
		Key:    key,
	}
}

// Build describes all aspects of a kernel build.
type Build struct {
	ID              string
	SyzkallerCommit string
	CompilerID      string
	KernelRepo      string
	KernelBranch    string
	KernelCommit    string
	KernelConfig    []byte
}

func (dash *Dashboard) UploadBuild(build *Build) error {
	return dash.query("upload_build", build, nil)
}

// Crash describes a single kernel crash (potentially with repro).
type Crash struct {
	Manager     string
	BuildID     string // refers to Build.ID
	Title       string
	Maintainers []string
	Log         []byte
	Report      []byte
	// The following is optional and is filled only after repro.
	ReproOpts []byte
	ReproSyz  []byte
	ReproC    []byte
}

func (dash *Dashboard) ReportCrash(crash *Crash) error {
	return dash.query("report_crash", crash, nil)
}

// FailedRepro describes a failed repro attempt.
type FailedRepro struct {
	Manager string
	BuildID string
	Title   string
}

func (dash *Dashboard) ReportFailedRepro(repro *FailedRepro) error {
	return dash.query("report_failed_repro", repro, nil)
}

func (dash *Dashboard) query(method string, req, reply interface{}) error {
	values := make(url.Values)
	values.Add("client", dash.Client)
	values.Add("key", dash.Key)
	values.Add("method", method)
	var body io.Reader
	gzipped := false
	if req != nil {
		data, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %v", err)
		}
		if strings.HasPrefix(dash.Addr, "http://localhost:") {
			// This is probably dev_appserver which does not support gzip.
			body = bytes.NewReader(data)
		} else {
			buf := new(bytes.Buffer)
			gz := gzip.NewWriter(buf)
			if _, err := gz.Write(data); err != nil {
				return err
			}
			if err := gz.Close(); err != nil {
				return err
			}
			body = buf
			gzipped = true
		}
	}
	url := fmt.Sprintf("%v/api?%v", dash.Addr, values.Encode())
	r, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
		if gzipped {
			r.Header.Set("Content-Encoding", "gzip")
		}
	}
	resp, err := http.DefaultClient.Do(r)
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
