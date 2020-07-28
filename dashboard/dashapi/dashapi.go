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
	"net/mail"
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
	Manager             string
	ID                  string
	OS                  string
	Arch                string
	VMArch              string
	SyzkallerCommit     string
	SyzkallerCommitDate time.Time
	CompilerID          string
	KernelRepo          string
	KernelBranch        string
	KernelCommit        string
	KernelCommitTitle   string
	KernelCommitDate    time.Time
	KernelConfig        []byte
	Commits             []string // see BuilderPoll
	FixCommits          []Commit
}

type Commit struct {
	Hash       string
	Title      string
	Author     string
	AuthorName string
	CC         []string // deprecated in favor of Recipients
	Recipients Recipients
	BugIDs     []string // ID's extracted from Reported-by tags
	Date       time.Time
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
	Managers map[string]ManagerJobs
}

type ManagerJobs struct {
	TestPatches bool
	BisectCause bool
	BisectFix   bool
}

type JobPollResp struct {
	ID                string
	Type              JobType
	Manager           string
	KernelRepo        string
	KernelBranch      string
	KernelCommit      string
	KernelCommitTitle string
	KernelCommitDate  time.Time
	KernelConfig      []byte
	SyzkallerCommit   string
	Patch             []byte
	ReproOpts         []byte
	ReproSyz          []byte
	ReproC            []byte
}

type JobDoneReq struct {
	ID          string
	Build       Build
	Error       []byte
	Log         []byte // bisection log
	CrashTitle  string
	CrashLog    []byte
	CrashReport []byte
	// Bisection results:
	// If there is 0 commits:
	//  - still happens on HEAD for fix bisection
	//  - already happened on the oldest release
	// If there is 1 commits: bisection result (cause or fix).
	// If there are more than 1: suspected commits due to skips (broken build/boot).
	Commits []Commit
	Flags   JobDoneFlags
}

type JobType int

const (
	JobTestPatch JobType = iota
	JobBisectCause
	JobBisectFix
)

type JobDoneFlags int64

const (
	BisectResultMerge   JobDoneFlags = 1 << iota // bisected to a merge commit
	BisectResultNoop                             // commit does not affect resulting kernel binary
	BisectResultRelease                          // commit is a kernel release
	BisectResultIgnore                           // this particular commit should be ignored, see syz-ci/jobs.go
)

func (dash *Dashboard) JobPoll(req *JobPollReq) (*JobPollResp, error) {
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

type CommitPollResp struct {
	ReportEmail string
	Repos       []Repo
	Commits     []string
}

type CommitPollResultReq struct {
	Commits []Commit
}

type Repo struct {
	URL    string
	Branch string
}

func (dash *Dashboard) CommitPoll() (*CommitPollResp, error) {
	resp := new(CommitPollResp)
	err := dash.Query("commit_poll", nil, resp)
	return resp, err
}

func (dash *Dashboard) UploadCommits(commits []Commit) error {
	if len(commits) == 0 {
		return nil
	}
	return dash.Query("upload_commits", &CommitPollResultReq{commits}, nil)
}

// Crash describes a single kernel crash (potentially with repro).
type Crash struct {
	BuildID     string // refers to Build.ID
	Title       string
	Corrupted   bool     // report is corrupted (corrupted title, no stacks, etc)
	Maintainers []string // deprecated in favor of Recipients
	Recipients  Recipients
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
	Type              ReportType
	Namespace         string
	Config            []byte
	ID                string
	JobID             string
	ExtID             string // arbitrary reporting ID forwarded from BugUpdate.ExtID
	First             bool   // Set for first report for this bug (Type == ReportNew).
	Moderation        bool
	NoRepro           bool // We don't expect repro (e.g. for build/boot errors).
	Title             string
	Link              string   // link to the bug on dashboard
	CreditEmail       string   // email for the Reported-by tag
	Maintainers       []string // deprecated in favor of Recipients
	CC                []string // deprecated in favor of Recipients
	Recipients        Recipients
	OS                string
	Arch              string
	VMArch            string
	UserSpaceArch     string // user-space arch as kernel developers know it (rather than Go names)
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

	CrashTitle     string // job execution crash title
	Error          []byte // job execution error
	ErrorLink      string
	ErrorTruncated bool // full Error text is too large and was truncated
	PatchLink      string
	BisectCause    *BisectResult
	BisectFix      *BisectResult
}

type BisectResult struct {
	Commit          *Commit   // for conclusive bisection
	Commits         []*Commit // for inconclusive bisection
	LogLink         string
	CrashLogLink    string
	CrashReportLink string
	Fix             bool
}

type BugUpdate struct {
	ID           string // copied from BugReport
	JobID        string // copied from BugReport
	ExtID        string
	Link         string
	Status       BugStatus
	ReproLevel   ReproLevel
	DupOf        string
	OnHold       bool     // If set for open bugs, don't upstream this bug.
	Notification bool     // Reply to a notification.
	FixCommits   []string // Titles of commits that fix this bug.
	CC           []string // Additional emails to add to CC list in future emails.
	CrashID      int64
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

type BugNotification struct {
	Type        BugNotif
	Namespace   string
	Config      []byte
	ID          string
	ExtID       string // arbitrary reporting ID forwarded from BugUpdate.ExtID
	Title       string
	Text        string   // meaning depends on Type
	CC          []string // deprecated in favor of Recipients
	Maintainers []string // deprecated in favor of Recipients
	Recipients  Recipients
	// Public is what we want all involved people to see (e.g. if we notify about a wrong commit title,
	// people need to see it and provide the right title). Not public is what we want to send only
	// to a minimal set of recipients (our mailing list) (e.g. notification about an obsoleted bug
	// is mostly "for the record").
	Public bool
}

type PollNotificationsRequest struct {
	Type string
}

type PollNotificationsResponse struct {
	Notifications []*BugNotification
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

func (dash *Dashboard) ReportingPollNotifications(typ string) (*PollNotificationsResponse, error) {
	req := &PollNotificationsRequest{
		Type: typ,
	}
	resp := new(PollNotificationsResponse)
	if err := dash.Query("reporting_poll_notifs", req, resp); err != nil {
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
	UpTime     time.Duration
	Corpus     uint64
	PCs        uint64 // coverage
	Cover      uint64 // what we call feedback signal everywhere else
	CrashTypes uint64

	// Delta since last sync:
	FuzzingTime       time.Duration
	Crashes           uint64
	SuppressedCrashes uint64
	Execs             uint64
}

func (dash *Dashboard) UploadManagerStats(req *ManagerStatsReq) error {
	return dash.Query("manager_stats", req, nil)
}

type BugListResp struct {
	List []string
}

func (dash *Dashboard) BugList() (*BugListResp, error) {
	resp := new(BugListResp)
	err := dash.Query("bug_list", nil, resp)
	return resp, err
}

type LoadBugReq struct {
	ID string
}

type LoadBugResp struct {
	ID              string
	Title           string
	Status          string
	SyzkallerCommit string
	Arch            string
	ReproOpts       []byte
	ReproSyz        []byte
	ReproC          []byte
}

func (dash *Dashboard) LoadBug(id string) (*LoadBugResp, error) {
	req := LoadBugReq{id}
	resp := new(LoadBugResp)
	err := dash.Query("load_bug", req, resp)
	return resp, err
}

type (
	BugStatus  int
	BugNotif   int
	ReproLevel int
	ReportType int
)

const (
	BugStatusOpen BugStatus = iota
	BugStatusUpstream
	BugStatusInvalid
	BugStatusDup
	BugStatusUpdate // aux info update (i.e. ExtID/Link/CC)
	BugStatusUnCC   // don't CC sender on any future communication
)

const (
	// Upstream bug into next reporting.
	// If the action succeeds, reporting sends BugStatusUpstream update.
	BugNotifUpstream BugNotif = iota
	// Bug needs to be closed as obsoleted.
	// If the action succeeds, reporting sends BugStatusInvalid update.
	BugNotifObsoleted
	// Bug fixing commit can't be discovered (wrong commit title).
	BugNotifBadCommit
)

const (
	ReproLevelNone ReproLevel = iota
	ReproLevelSyz
	ReproLevelC
)

const (
	ReportNew         ReportType = iota // First report for this bug in the reporting stage.
	ReportRepro                         // Found repro for an already reported bug.
	ReportTestPatch                     // Patch testing result.
	ReportBisectCause                   // Cause bisection result for an already reported bug.
	ReportBisectFix                     // Fix bisection result for an already reported bug.
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

type RecipientType int

const (
	To RecipientType = iota
	Cc
)

func (t RecipientType) String() string {
	return [...]string{"To", "Cc"}[t]
}

type RecipientInfo struct {
	Address mail.Address
	Type    RecipientType
}

type Recipients []RecipientInfo

func (r Recipients) Len() int           { return len(r) }
func (r Recipients) Less(i, j int) bool { return r[i].Address.Address < r[j].Address.Address }
func (r Recipients) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
