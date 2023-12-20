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
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/auth"
)

type Dashboard struct {
	Client string
	Addr   string
	Key    string
	ctor   RequestCtor
	doer   RequestDoer
	logger RequestLogger
	// Yes, we have the ability to set custom constructor, doer and logger, but
	// there are also cases when we just want to mock the whole request processing.
	// Implementing that on top of http.Request/http.Response would complicate the
	// code too much.
	mocker       RequestMocker
	errorHandler func(error)
}

func New(client, addr, key string) (*Dashboard, error) {
	return NewCustom(client, addr, key, http.NewRequest, http.DefaultClient.Do, nil, nil)
}

type (
	RequestCtor   func(method, url string, body io.Reader) (*http.Request, error)
	RequestDoer   func(req *http.Request) (*http.Response, error)
	RequestLogger func(msg string, args ...interface{})
	RequestMocker func(method string, req, resp interface{}) error
)

// key == "" indicates that the ambient GCE service account authority
// should be used as a bearer token.
func NewCustom(client, addr, key string, ctor RequestCtor, doer RequestDoer,
	logger RequestLogger, errorHandler func(error)) (*Dashboard, error) {
	wrappedDoer := doer
	if key == "" {
		tokenCache, err := auth.MakeCache(ctor, doer)
		if err != nil {
			return nil, err
		}
		wrappedDoer = func(req *http.Request) (*http.Response, error) {
			token, err := tokenCache.Get(time.Now())
			if err != nil {
				return nil, err
			}
			req.Header.Add("Authorization", token)
			return doer(req)
		}
	}
	return &Dashboard{
		Client:       client,
		Addr:         addr,
		Key:          key,
		ctor:         ctor,
		doer:         wrappedDoer,
		logger:       logger,
		errorHandler: errorHandler,
	}, nil
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
	Assets              []NewAsset
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
	Link       string // set if the commit is a part of a reply
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
//   - syz-ci sends JobResetReq to indicate that no previously started jobs
//     are any longer in progress.
//   - syz-ci sends JobPollReq periodically to check for new jobs,
//     request contains list of managers that this syz-ci runs.
//   - dashboard replies with JobPollResp that contains job details,
//     if no new jobs available ID is set to empty string.
//   - when syz-ci finishes the job, it sends JobDoneReq which contains
//     job execution result (Build, Crash or Error details),
//     ID must match JobPollResp.ID.

type JobResetReq struct {
	Managers []string
}

type JobPollReq struct {
	Managers map[string]ManagerJobs
}

type ManagerJobs struct {
	TestPatches bool
	BisectCause bool
	BisectFix   bool
}

func (m ManagerJobs) Any() bool {
	return m.TestPatches || m.BisectCause || m.BisectFix
}

type JobPollResp struct {
	ID         string
	Type       JobType
	Manager    string
	KernelRepo string
	// KernelBranch is used for patch testing and serves as the current HEAD
	// for bisections.
	KernelBranch    string
	MergeBaseRepo   string
	MergeBaseBranch string
	// Bisection starts from KernelCommit.
	KernelCommit      string
	KernelCommitTitle string
	KernelConfig      []byte
	SyzkallerCommit   string
	Patch             []byte
	ReproOpts         []byte
	ReproSyz          []byte
	ReproC            []byte
}

type JobDoneReq struct {
	ID             string
	Build          Build
	Error          []byte
	Log            []byte // bisection log
	CrashTitle     string
	CrashAltTitles []string
	CrashLog       []byte
	CrashReport    []byte
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
	BisectResultMerge      JobDoneFlags = 1 << iota // bisected to a merge commit
	BisectResultNoop                                // commit does not affect resulting kernel binary
	BisectResultRelease                             // commit is a kernel release
	BisectResultIgnore                              // this particular commit should be ignored, see syz-ci/jobs.go
	BisectResultInfraError                          // the bisect failed due to an infrastructure problem
)

func (flags JobDoneFlags) String() string {
	if flags&BisectResultInfraError != 0 {
		return "[infra failure]"
	}
	res := ""
	if flags&BisectResultMerge != 0 {
		res += "merge "
	}
	if flags&BisectResultNoop != 0 {
		res += "no-op "
	}
	if flags&BisectResultRelease != 0 {
		res += "release "
	}
	if flags&BisectResultIgnore != 0 {
		res += "ignored "
	}
	if res == "" {
		return res
	}
	return "[" + res + "commit]"
}

func (dash *Dashboard) JobPoll(req *JobPollReq) (*JobPollResp, error) {
	resp := new(JobPollResp)
	err := dash.Query("job_poll", req, resp)
	return resp, err
}

func (dash *Dashboard) JobDone(req *JobDoneReq) error {
	return dash.Query("job_done", req, nil)
}

func (dash *Dashboard) JobReset(req *JobResetReq) error {
	return dash.Query("job_reset", req, nil)
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

type CrashFlags int64

const (
	CrashUnderStrace CrashFlags = 1 << iota
)

// Crash describes a single kernel crash (potentially with repro).
type Crash struct {
	BuildID     string // refers to Build.ID
	Title       string
	AltTitles   []string // alternative titles, used for better deduplication
	Corrupted   bool     // report is corrupted (corrupted title, no stacks, etc)
	Suppressed  bool
	Maintainers []string // deprecated in favor of Recipients
	Recipients  Recipients
	Log         []byte
	Flags       CrashFlags
	Report      []byte
	MachineInfo []byte
	Assets      []NewAsset
	GuiltyFiles []string
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
	BuildID      string
	Title        string
	Corrupted    bool
	Suppressed   bool
	MayBeMissing bool
	ReproLog     []byte
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
	BugStatus         BugStatus
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
	BuildID           string
	BuildTime         time.Time
	CompilerID        string
	KernelRepo        string
	KernelRepoAlias   string
	KernelBranch      string
	KernelCommit      string
	KernelCommitTitle string
	KernelCommitDate  time.Time
	KernelConfig      []byte
	KernelConfigLink  string
	SyzkallerCommit   string
	Log               []byte
	LogLink           string
	LogHasStrace      bool
	Report            []byte
	ReportLink        string
	ReproC            []byte
	ReproCLink        string
	ReproSyz          []byte
	ReproSyzLink      string
	ReproOpts         []byte
	MachineInfo       []byte
	MachineInfoLink   string
	Manager           string
	CrashID           int64 // returned back in BugUpdate
	CrashTime         time.Time
	NumCrashes        int64
	HappenedOn        []string // list of kernel repo aliases

	CrashTitle     string // job execution crash title
	Error          []byte // job execution error
	ErrorLink      string
	ErrorTruncated bool // full Error text is too large and was truncated
	PatchLink      string
	BisectCause    *BisectResult
	BisectFix      *BisectResult
	Assets         []Asset
	Subsystems     []BugSubsystem
	ReportElements *ReportElements
	LabelMessages  map[string]string // notification messages for bug labels
}

type ReportElements struct {
	GuiltyFiles []string
}

type BugSubsystem struct {
	Name  string
	Link  string
	SetBy string
}

type Asset struct {
	Title       string
	DownloadURL string
	Type        AssetType
}

type AssetType string

// Asset types used throughout the system.
// DO NOT change them, this will break compatibility with DB content.
const (
	BootableDisk       AssetType = "bootable_disk"
	NonBootableDisk    AssetType = "non_bootable_disk"
	KernelObject       AssetType = "kernel_object"
	KernelImage        AssetType = "kernel_image"
	HTMLCoverageReport AssetType = "html_coverage_report"
	MountInRepro       AssetType = "mount_in_repro"
)

type BisectResult struct {
	Commit          *Commit   // for conclusive bisection
	Commits         []*Commit // for inconclusive bisection
	LogLink         string
	CrashLogLink    string
	CrashReportLink string
	Fix             bool
	CrossTree       bool
}

type BugListReport struct {
	ID          string
	Created     time.Time
	Config      []byte
	Bugs        []BugListItem
	TotalStats  BugListReportStats
	PeriodStats BugListReportStats
	PeriodDays  int
	Link        string
	Subsystem   string
	Maintainers []string
	Moderation  bool
}

type BugListReportStats struct {
	Reported int
	LowPrio  int
	Fixed    int
}

// BugListItem represents a single bug from the BugListReport entity.
type BugListItem struct {
	ID         string
	Title      string
	Link       string
	ReproLevel ReproLevel
	Hits       int64
}

type BugListUpdate struct {
	ID      string // copied from BugListReport
	ExtID   string
	Link    string
	Command BugListUpdateCommand
}

type BugListUpdateCommand string

const (
	BugListSentCmd       BugListUpdateCommand = "sent"
	BugListUpdateCmd     BugListUpdateCommand = "update"
	BugListUpstreamCmd   BugListUpdateCommand = "upstream"
	BugListRegenerateCmd BugListUpdateCommand = "regenerate"
)

type BugUpdate struct {
	ID              string // copied from BugReport
	JobID           string // copied from BugReport
	ExtID           string
	Link            string
	Status          BugStatus
	StatusReason    BugStatusReason
	Labels          []string // the reported labels
	ReproLevel      ReproLevel
	DupOf           string
	OnHold          bool     // If set for open bugs, don't upstream this bug.
	Notification    bool     // Reply to a notification.
	ResetFixCommits bool     // Remove all commits (empty FixCommits means leave intact).
	FixCommits      []string // Titles of commits that fix this bug.
	CC              []string // Additional emails to add to CC list in future emails.

	CrashID int64 // This is a deprecated field, left here for backward compatibility.

	// The new interface that allows to report and unreport several crashes at the same time.
	// This is not relevant for emails, but may be important for external reportings.
	ReportCrashIDs   []int64
	UnreportCrashIDs []int64
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
	Label       string   // for BugNotifLabel Type specifies the exact label
	CC          []string // deprecated in favor of Recipients
	Maintainers []string // deprecated in favor of Recipients
	Link        string
	Recipients  Recipients
	TreeJobs    []*JobInfo // set for some BugNotifLabel
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

type DiscussionSource string

const (
	NoDiscussion   DiscussionSource = ""
	DiscussionLore DiscussionSource = "lore"
)

type DiscussionType string

const (
	DiscussionReport   DiscussionType = "report"
	DiscussionPatch    DiscussionType = "patch"
	DiscussionReminder DiscussionType = "reminder"
	DiscussionMention  DiscussionType = "mention"
)

type Discussion struct {
	ID       string
	Source   DiscussionSource
	Type     DiscussionType
	Subject  string
	BugIDs   []string
	Messages []DiscussionMessage
}

type DiscussionMessage struct {
	ID       string
	External bool // true if the message is not from the bot itself
	Time     time.Time
	Email    string // not saved to the DB
}

type SaveDiscussionReq struct {
	// If the discussion already exists, Messages and BugIDs will be appended to it.
	Discussion *Discussion
}

func (dash *Dashboard) SaveDiscussion(req *SaveDiscussionReq) error {
	return dash.Query("save_discussion", req, nil)
}

type TestPatchRequest struct {
	BugID  string
	Link   string
	User   string
	Repo   string
	Branch string
	Patch  []byte
}

type TestPatchReply struct {
	ErrorText string
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

func (dash *Dashboard) NewTestJob(upd *TestPatchRequest) (*TestPatchReply, error) {
	resp := new(TestPatchReply)
	if err := dash.Query("new_test_job", upd, resp); err != nil {
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

// Asset lifetime:
// 1. syz-ci uploads it to GCS and reports to the dashboard via add_build_asset.
// 2. dashboard periodically checks if the asset is still needed.
// 3. syz-ci queries needed_assets to figure out which assets are still needed.
// 4. Once an asset is not needed, syz-ci removes the corresponding file.
type NewAsset struct {
	DownloadURL string
	Type        AssetType
}

type AddBuildAssetsReq struct {
	BuildID string
	Assets  []NewAsset
}

func (dash *Dashboard) AddBuildAssets(req *AddBuildAssetsReq) error {
	return dash.Query("add_build_assets", req, nil)
}

type NeededAssetsResp struct {
	DownloadURLs []string
}

func (dash *Dashboard) NeededAssetsList() (*NeededAssetsResp, error) {
	resp := new(NeededAssetsResp)
	err := dash.Query("needed_assets", nil, resp)
	return resp, err
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

func (dash *Dashboard) LoadBug(id string) (*BugReport, error) {
	req := LoadBugReq{id}
	resp := new(BugReport)
	err := dash.Query("load_bug", req, resp)
	return resp, err
}

type LoadFullBugReq struct {
	BugID string
}

type FullBugInfo struct {
	SimilarBugs  []*SimilarBugInfo
	BisectCause  *BugReport
	BisectFix    *BugReport
	Crashes      []*BugReport
	TreeJobs     []*JobInfo
	FixCandidate *BugReport
}

type SimilarBugInfo struct {
	Title      string
	Status     BugStatus
	Namespace  string
	Link       string
	ReportLink string
	Closed     time.Time
	ReproLevel ReproLevel
}

func (dash *Dashboard) LoadFullBug(req *LoadFullBugReq) (*FullBugInfo, error) {
	resp := new(FullBugInfo)
	err := dash.Query("load_full_bug", req, resp)
	return resp, err
}

type UpdateReportReq struct {
	BugID       string
	CrashID     int64
	GuiltyFiles *[]string
}

func (dash *Dashboard) UpdateReport(req *UpdateReportReq) error {
	return dash.Query("update_report", req, nil)
}

type (
	BugStatus       int
	BugStatusReason string
	BugNotif        int
	ReproLevel      int
	ReportType      int
)

const (
	BugStatusOpen BugStatus = iota
	BugStatusUpstream
	BugStatusInvalid
	BugStatusDup
	BugStatusUpdate // aux info update (i.e. ExtID/Link/CC)
	BugStatusUnCC   // don't CC sender on any future communication
	BugStatusFixed
)

const (
	InvalidatedByRevokedRepro = BugStatusReason("invalid_no_repro")
	InvalidatedByNoActivity   = BugStatusReason("invalid_no_activity")
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
	// New bug label has been assigned (only if enabled).
	// Text contains the custome message that needs to be delivered to the user.
	BugNotifLabel
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

type JobInfo struct {
	JobKey           string
	Type             JobType
	Flags            JobDoneFlags
	Created          time.Time
	BugLink          string
	ExternalLink     string
	User             string
	Reporting        string
	Namespace        string
	Manager          string
	BugTitle         string
	BugID            string
	KernelRepo       string
	KernelBranch     string
	KernelAlias      string
	KernelCommit     string
	KernelCommitLink string
	KernelLink       string
	PatchLink        string
	Attempts         int
	Started          time.Time
	Finished         time.Time
	Duration         time.Duration
	CrashTitle       string
	CrashLogLink     string
	CrashReportLink  string
	LogLink          string
	ErrorLink        string
	ReproCLink       string
	ReproSyzLink     string
	Commit           *Commit   // for conclusive bisection
	Commits          []*Commit // for inconclusive bisection
	Reported         bool
	InvalidatedBy    string
	TreeOrigin       bool
	OnMergeBase      bool
}

func (dash *Dashboard) Query(method string, req, reply interface{}) error {
	if dash.logger != nil {
		dash.logger("API(%v): %#v", method, req)
	}
	if dash.mocker != nil {
		return dash.mocker(method, req, reply)
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
			return fmt.Errorf("failed to marshal request: %w", err)
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
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with %v: %s", resp.Status, data)
	}
	if reply != nil {
		if err := json.NewDecoder(resp.Body).Decode(reply); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
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
