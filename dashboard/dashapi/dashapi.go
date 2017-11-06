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
	"reflect"
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
	Manager         string
	ID              string
	OS              string
	Arch            string
	VMArch          string
	SyzkallerCommit string
	CompilerID      string
	KernelRepo      string
	KernelBranch    string
	KernelCommit    string
	KernelConfig    []byte
	Commits         []string // see BuilderPoll
}

func (dash *Dashboard) UploadBuild(build *Build) error {
	return dash.query("upload_build", build, nil)
}

// BuilderPoll request is done by kernel builder before uploading a new build
// with UploadBuild request. Response contains list of commits that dashboard
// is interested in (i.e. commits that fix open bugs). When uploading a new
// build builder should pass subset of the commits that are present in the build
// in Build.Commits field.

type BuilderPollReq struct {
	Manager string
}

type BuilderPollResp struct {
	PendingCommits []string
}

func (dash *Dashboard) BuilderPoll(manager string) (*BuilderPollResp, error) {
	req := &BuilderPollReq{
		Manager: manager,
	}
	resp := new(BuilderPollResp)
	err := dash.query("builder_poll", req, resp)
	return resp, err
}

// Crash describes a single kernel crash (potentially with repro).
type Crash struct {
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

type ReportCrashResp struct {
	NeedRepro bool
}

func (dash *Dashboard) ReportCrash(crash *Crash) (*ReportCrashResp, error) {
	resp := new(ReportCrashResp)
	err := dash.query("report_crash", crash, resp)
	return resp, err
}

// CrashID is a short summary of a crash for repro queires.
type CrashID struct {
	BuildID string
	Title   string
}

type NeedReproResp struct {
	NeedRepro bool
}

// NeedRepro checks if dashboard needs a repro for this crash or not.
func (dash *Dashboard) NeedRepro(crash *CrashID) (bool, error) {
	resp := new(NeedReproResp)
	err := dash.query("need_repro", crash, resp)
	return resp.NeedRepro, err
}

// ReportFailedRepro notifies dashboard about a failed repro attempt for the crash.
func (dash *Dashboard) ReportFailedRepro(crash *CrashID) error {
	return dash.query("report_failed_repro", crash, nil)
}

type LogEntry struct {
	Name string
	Text string
}

// Centralized logging on dashboard.
func (dash *Dashboard) LogError(name, msg string, args ...interface{}) {
	req := &LogEntry{
		Name: name,
		Text: fmt.Sprintf(msg, args...),
	}
	dash.query("log_error", req, nil)
}

// BugReport describes a single bug.
// Used by dashboard external reporting.
type BugReport struct {
	Namespace    string
	Config       []byte
	ID           string
	ExtID        string // arbitrary reporting ID forwarded from BugUpdate.ExtID
	First        bool   // Set for first report for this bug.
	Title        string
	Maintainers  []string
	CC           []string // additional CC emails
	OS           string
	Arch         string
	VMArch       string
	CompilerID   string
	KernelRepo   string
	KernelBranch string
	KernelCommit string
	KernelConfig []byte
	Log          []byte
	Report       []byte
	ReproC       []byte
	ReproSyz     []byte
}

type BugUpdate struct {
	ID         string
	ExtID      string
	Link       string
	Status     BugStatus
	ReproLevel ReproLevel
	DupOf      string
	FixCommits []string // Titles of commits that fix this bug.
	CC         []string // Additional emails to add to CC list in future emails.
}

type BugUpdateReply struct {
	// Bug update can fail for 2 reason:
	//  - update does not pass logical validataion, in this case OK=false
	//  - internal/datastore error, in this case Error=true
	OK    bool
	Error bool
	Text  string
}

type PollRequest struct {
	Type string
}

type PollResponse struct {
	Reports []*BugReport
}

type (
	BugStatus  int
	ReproLevel int
)

const (
	BugStatusOpen BugStatus = iota
	BugStatusUpstream
	BugStatusInvalid
	BugStatusDup
	BugStatusUpdate // aux info update (i.e. ExtID/Link/CC)
)

const (
	ReproLevelNone ReproLevel = iota
	ReproLevelSyz
	ReproLevelC
)

func (dash *Dashboard) query(method string, req, reply interface{}) error {
	return Query(dash.Client, dash.Addr, dash.Key, method,
		http.NewRequest, http.DefaultClient.Do, req, reply)
}

type (
	RequestCtor func(method, url string, body io.Reader) (*http.Request, error)
	RequestDoer func(req *http.Request) (*http.Response, error)
)

func Query(client, addr, key, method string, ctor RequestCtor, doer RequestDoer, req, reply interface{}) error {
	if reply != nil {
		// json decoding behavior is somewhat surprising
		// (see // https://github.com/golang/go/issues/21092).
		// To avoid any surprises, we zero the reply.
		typ := reflect.TypeOf(reply)
		if typ.Kind() != reflect.Ptr {
			return fmt.Errorf("resp must be a pointer")
		}
		reflect.ValueOf(reply).Elem().Set(reflect.New(typ.Elem()).Elem())
	}
	values := make(url.Values)
	values.Add("client", client)
	values.Add("key", key)
	values.Add("method", method)
	var body io.Reader
	gzipped := false
	if req != nil {
		data, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %v", err)
		}
		if len(data) < 100 || addr == "" || strings.HasPrefix(addr, "http://localhost:") {
			// Don't bother compressing tiny requests.
			// Don't compress for dev_appserver which does not support gzip.
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
	url := fmt.Sprintf("%v/api?%v", addr, values.Encode())
	r, err := ctor("POST", url, body)
	if err != nil {
		return err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
		if gzipped {
			r.Header.Set("Content-Encoding", "gzip")
		}
	}
	resp, err := doer(r)
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
