// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package dashapi defines data structures used in dashboard communication
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
	"time"
)

type Dashboard struct {
	Client       string
	Addr         string
	Key          string
	ctor         RequestCtor
	doer         RequestDoer
	logger       RequestLogger
	errorHandler func(error)
}

func New(client, addr, key string) *Dashboard {
	return NewCustom(client, addr, key, http.NewRequest, http.DefaultClient.Do, nil, nil)
}

type (
	RequestCtor   func(method, url string, body io.Reader) (*http.Request, error)
	RequestDoer   func(req *http.Request) (*http.Response, error)
	RequestLogger func(msg string, args ...interface{})
)

func NewCustom(client, addr, key string, ctor RequestCtor, doer RequestDoer,
	logger RequestLogger, errorHandler func(error)) *Dashboard {
	return &Dashboard{
		Client:       client,
		Addr:         addr,
		Key:          key,
		ctor:         ctor,
		doer:         doer,
		logger:       logger,
		errorHandler: errorHandler,
	}
}

// Build describes all aspects of a kernel build.
type Build struct {
	Manager           string
	ID                string
	OS                string
	Arch              string
	VMArch            string
	SyzkallerCommit   string
	CompilerID        string
	KernelRepo        string
	KernelBranch      string
	KernelCommit      string
	KernelCommitTitle string
	KernelCommitDate  time.Time
	KernelConfig      []byte
	Commits           []string // see BuilderPoll
	FixCommits        []FixCommit
}

type FixCommit struct {
	Title string
	BugID string
}

func (dash *Dashboard) UploadBuild(build *Build) error {
	return dash.Query("upload_build", build, nil)
}

// BuilderPoll request is done by kernel builder before uploading a new build
// with UploadBuild request. Response contains list of commit titles that
// dashboard is interested in (i.e. commits that fix open bugs) and email that
// appears in Reported-by tags for bug ID extraction. When uploading a new build
// builder will pass subset of the commit titles that are present in the build
// in Build.Commits field and list of {bug ID, commit title} pairs extracted
// from git log.

type BuilderPollReq struct {
	Manager string
}

type BuilderPollResp struct {
	PendingCommits []string
	ReportEmail    string
}

func (dash *Dashboard) BuilderPoll(manager string) (*BuilderPollResp, error) {
	req := &BuilderPollReq{
		Manager: manager,
	}
	resp := new(BuilderPollResp)
	err := dash.Query("builder_poll", req, resp)
	return resp, err
}

// Jobs workflow:
//   - syz-ci sends JobPollReq periodically to check for new jobs,
//     request contains list of managers that this syz-ci runs.
//   - dashboard replies with JobPollResp that contains job details,
//     if no new jobs available ID is set to empty string.
//   - when syz-ci finishes the job, it sends JobDoneReq which contains
//     job execution result (Build, Crash or Error details),
//     ID must match JobPollResp.ID.

type JobPollReq struct {
	Managers []string
}

type JobPollResp struct {
	ID              string
	Manager         string
	KernelRepo      string
	KernelBranch    string
	KernelConfig    []byte
	SyzkallerCommit string
	Patch           []byte
	ReproOpts       []byte
	ReproSyz        []byte
	ReproC          []byte
}

type JobDoneReq struct {
	ID          string
	Build       Build
	Error       []byte
	CrashTitle  string
	CrashLog    []byte
	CrashReport []byte
}

func (dash *Dashboard) JobPoll(managers []string) (*JobPollResp, error) {
	req := &JobPollReq{Managers: managers}
	resp := new(JobPollResp)
	err := dash.Query("job_poll", req, resp)
	return resp, err
}

func (dash *Dashboard) JobDone(req *JobDoneReq) error {
	return dash.Query("job_done", req, nil)
}

type BuildErrorReq struct {
	Build Build
	Crash Crash
}

func (dash *Dashboard) ReportBuildError(req *BuildErrorReq) error {
	return dash.Query("report_build_error", req, nil)
}

// Crash describes a single kernel crash (potentially with repro).
type Crash struct {
	BuildID     string // refers to Build.ID
	Title       string
	Corrupted   bool // report is corrupted (corrupted title, no stacks, etc)
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
	err := dash.Query("report_crash", crash, resp)
	return resp, err
}

// CrashID is a short summary of a crash for repro queries.
type CrashID struct {
	BuildID   string
	Title     string
	Corrupted bool
}

type NeedReproResp struct {
	NeedRepro bool
}

// NeedRepro checks if dashboard needs a repro for this crash or not.
func (dash *Dashboard) NeedRepro(crash *CrashID) (bool, error) {
	resp := new(NeedReproResp)
	err := dash.Query("need_repro", crash, resp)
	return resp.NeedRepro, err
}

// ReportFailedRepro notifies dashboard about a failed repro attempt for the crash.
func (dash *Dashboard) ReportFailedRepro(crash *CrashID) error {
	return dash.Query("report_failed_repro", crash, nil)
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
	dash.Query("log_error", req, nil)
}

// BugReport describes a single bug.
// Used by dashboard external reporting.
type BugReport struct {
	Namespace         string
	Config            []byte
	ID                string
	JobID             string
	ExtID             string // arbitrary reporting ID forwarded from BugUpdate.ExtID
	First             bool   // Set for first report for this bug.
	Title             string
	Maintainers       []string
	CC                []string // additional CC emails
	OS                string
	Arch              string
	VMArch            string
	CompilerID        string
	KernelRepo        string
	KernelRepoAlias   string
	KernelBranch      string
	KernelCommit      string
	KernelCommitTitle string
	KernelCommitDate  time.Time
	KernelConfig      []byte
	KernelConfigLink  string
	Log               []byte
	LogLink           string
	Report            []byte
	ReportLink        string
	ReproC            []byte
	ReproCLink        string
	ReproSyz          []byte
	ReproSyzLink      string
	CrashID           int64 // returned back in BugUpdate
	NumCrashes        int64
	HappenedOn        []string // list of kernel repo aliases

	CrashTitle string // job execution crash title
	Error      []byte // job execution error
	ErrorLink  string
	Patch      []byte // testing job patch
	PatchLink  string
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
	CrashID    int64
}

type BugUpdateReply struct {
	// Bug update can fail for 2 reason:
	//  - update does not pass logical validataion, in this case OK=false
	//  - internal/datastore error, in this case Error=true
	OK    bool
	Error bool
	Text  string
}

type PollBugsRequest struct {
	Type string
}

type PollBugsResponse struct {
	Reports []*BugReport
}

type PollClosedRequest struct {
	IDs []string
}

type PollClosedResponse struct {
	IDs []string
}

func (dash *Dashboard) ReportingPollBugs(typ string) (*PollBugsResponse, error) {
	req := &PollBugsRequest{
		Type: typ,
	}
	resp := new(PollBugsResponse)
	if err := dash.Query("reporting_poll_bugs", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (dash *Dashboard) ReportingPollClosed(ids []string) ([]string, error) {
	req := &PollClosedRequest{
		IDs: ids,
	}
	resp := new(PollClosedResponse)
	if err := dash.Query("reporting_poll_closed", req, resp); err != nil {
		return nil, err
	}
	return resp.IDs, nil
}

func (dash *Dashboard) ReportingUpdate(upd *BugUpdate) (*BugUpdateReply, error) {
	resp := new(BugUpdateReply)
	if err := dash.Query("reporting_update", upd, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type ManagerStatsReq struct {
	Name string
	Addr string

	// Current level:
	UpTime time.Duration
	Corpus uint64
	Cover  uint64

	// Delta since last sync:
	FuzzingTime time.Duration
	Crashes     uint64
	Execs       uint64
}

func (dash *Dashboard) UploadManagerStats(req *ManagerStatsReq) error {
	return dash.Query("manager_stats", req, nil)
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

func (dash *Dashboard) Query(method string, req, reply interface{}) error {
	if dash.logger != nil {
		dash.logger("API(%v): %#v", method, req)
	}
	err := dash.queryImpl(method, req, reply)
	if err != nil {
		if dash.logger != nil {
			dash.logger("API(%v): ERROR: %v", method, err)
		}
		if dash.errorHandler != nil {
			dash.errorHandler(err)
		}
		return err
	}
	if dash.logger != nil {
		dash.logger("API(%v): REPLY: %#v", method, reply)
	}
	return nil
}

func (dash *Dashboard) queryImpl(method string, req, reply interface{}) error {
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
	values.Add("client", dash.Client)
	values.Add("key", dash.Key)
	values.Add("method", method)
	if req != nil {
		data, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %v", err)
		}
		buf := new(bytes.Buffer)
		gz := gzip.NewWriter(buf)
		if _, err := gz.Write(data); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		values.Add("payload", buf.String())
	}
	r, err := dash.ctor("POST", fmt.Sprintf("%v/api", dash.Addr), strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := dash.doer(r)
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
