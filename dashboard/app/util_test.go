// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// The test uses aetest package that starts local dev_appserver and handles all requests locally:
// https://cloud.google.com/appengine/docs/standard/go/tools/localunittesting/reference

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/subsystem"
	"google.golang.org/appengine/v2/aetest"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
	aemail "google.golang.org/appengine/v2/mail"
	"google.golang.org/appengine/v2/user"
)

type Ctx struct {
	t                *testing.T
	inst             aetest.Instance
	ctx              context.Context
	mockedTime       time.Time
	emailSink        chan *aemail.Message
	transformContext func(context.Context) context.Context
	client           *apiClient
	client2          *apiClient
	publicClient     *apiClient
}

var skipDevAppserverTests = func() bool {
	_, err := exec.LookPath("dev_appserver.py")
	// Don't silently skip tests on CI, we should have gcloud sdk installed there.
	return err != nil && os.Getenv("SYZ_ENV") == "" ||
		os.Getenv("SYZ_SKIP_DEV_APPSERVER_TESTS") != ""
}()

func NewCtx(t *testing.T) *Ctx {
	if skipDevAppserverTests {
		t.Skip("skipping test (no dev_appserver.py)")
	}
	t.Parallel()
	inst, err := aetest.NewInstance(&aetest.Options{
		// Without this option datastore queries return data with slight delay,
		// which fails reporting tests.
		StronglyConsistentDatastore: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := inst.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Ctx{
		t:                t,
		inst:             inst,
		mockedTime:       time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		emailSink:        make(chan *aemail.Message, 100),
		transformContext: func(c context.Context) context.Context { return c },
	}
	c.client = c.makeClient(client1, password1, true)
	c.client2 = c.makeClient(client2, password2, true)
	c.publicClient = c.makeClient(clientPublicEmail, keyPublicEmail, true)
	c.ctx = registerRequest(r, c).Context()
	return c
}

func (c *Ctx) config() *GlobalConfig {
	return getConfig(c.ctx)
}

func (c *Ctx) expectOK(err error) {
	if err != nil {
		c.t.Helper()
		c.t.Fatalf("expected OK, got error: %v", err)
	}
}

func (c *Ctx) expectFail(msg string, err error) {
	c.t.Helper()
	if err == nil {
		c.t.Fatalf("expected to fail, but it does not")
	}
	if !strings.Contains(err.Error(), msg) {
		c.t.Fatalf("expected to fail with %q, but failed with %q", msg, err)
	}
}

func (c *Ctx) expectFailureStatus(err error, code int) {
	c.t.Helper()
	if err == nil {
		c.t.Fatalf("expected to fail as %d, but it does not", code)
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) || httpErr.Code != code {
		c.t.Fatalf("expected to fail as %d, but it failed as %v", code, err)
	}
}

func (c *Ctx) expectForbidden(err error) {
	c.expectFailureStatus(err, http.StatusForbidden)
}

func (c *Ctx) expectBadReqest(err error) {
	c.expectFailureStatus(err, http.StatusBadRequest)
}

func (c *Ctx) expectEQ(got, want interface{}) {
	if diff := cmp.Diff(got, want); diff != "" {
		c.t.Helper()
		c.t.Fatal(diff)
	}
}

func (c *Ctx) expectNE(got, want interface{}) {
	if reflect.DeepEqual(got, want) {
		c.t.Helper()
		c.t.Fatalf("equal: %#v", got)
	}
}

func (c *Ctx) expectTrue(v bool) {
	if !v {
		c.t.Helper()
		c.t.Fatal("failed")
	}
}

func caller(skip int) string {
	pcs := make([]uintptr, 10)
	n := runtime.Callers(skip+3, pcs)
	pcs = pcs[:n]
	frames := runtime.CallersFrames(pcs)
	stack := ""
	for {
		frame, more := frames.Next()
		if strings.HasPrefix(frame.Function, "testing.") {
			break
		}
		stack = fmt.Sprintf("%v:%v\n", filepath.Base(frame.File), frame.Line) + stack
		if !more {
			break
		}
	}
	if stack != "" {
		stack = stack[:len(stack)-1]
	}
	return stack
}

func (c *Ctx) Close() {
	defer c.inst.Close()
	if !c.t.Failed() {
		// To avoid per-day reporting limits for left-over emails.
		c.advanceTime(25 * time.Hour)
		// Ensure that we can render main page and all bugs in the final test state.
		_, err := c.GET("/test1")
		c.expectOK(err)
		_, err = c.GET("/test2")
		c.expectOK(err)
		_, err = c.GET("/test1/fixed")
		c.expectOK(err)
		_, err = c.GET("/test2/fixed")
		c.expectOK(err)
		_, err = c.GET("/admin")
		c.expectOK(err)
		var bugs []*Bug
		keys, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
		if err != nil {
			c.t.Errorf("ERROR: failed to query bugs: %v", err)
		}
		for _, key := range keys {
			_, err = c.GET(fmt.Sprintf("/bug?id=%v", key.StringID()))
			c.expectOK(err)
		}
		// No pending emails (tests need to consume them).
		_, err = c.GET("/cron/email_poll")
		c.expectOK(err)
		for len(c.emailSink) != 0 {
			c.t.Errorf("ERROR: leftover email: %v", (<-c.emailSink).Body)
		}
		// No pending external reports (tests need to consume them).
		resp, _ := c.client.ReportingPollBugs("test")
		for _, rep := range resp.Reports {
			c.t.Errorf("ERROR: leftover external report:\n%#v", rep)
		}
	}
	unregisterContext(c)
	validateGlobalConfig()
}

func (c *Ctx) advanceTime(d time.Duration) {
	c.mockedTime = c.mockedTime.Add(d)
}

func (c *Ctx) setSubsystems(ns string, list []*subsystem.Subsystem, rev int) {
	c.transformContext = func(c context.Context) context.Context {
		newConfig := replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
			ret := *cfg
			ret.Subsystems.Revision = rev
			if list == nil {
				ret.Subsystems.Service = nil
			} else {
				ret.Subsystems.Service = subsystem.MustMakeService(list)
			}
			return &ret
		})
		return contextWithConfig(c, newConfig)
	}
}

func (c *Ctx) setKernelRepos(ns string, list []KernelRepo) {
	c.transformContext = func(c context.Context) context.Context {
		newConfig := replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
			ret := *cfg
			ret.Repos = list
			return &ret
		})
		return contextWithConfig(c, newConfig)
	}
}

func (c *Ctx) setNoObsoletions() {
	c.transformContext = func(c context.Context) context.Context {
		return contextWithNoObsoletions(c)
	}
}

func (c *Ctx) updateReporting(ns, name string, f func(Reporting) Reporting) {
	c.transformContext = func(c context.Context) context.Context {
		return contextWithConfig(c, replaceReporting(c, ns, name, f))
	}
}

func (c *Ctx) decommissionManager(ns, oldManager, newManager string) {
	c.transformContext = func(c context.Context) context.Context {
		newConfig := replaceManagerConfig(c, ns, oldManager, func(cfg ConfigManager) ConfigManager {
			cfg.Decommissioned = true
			cfg.DelegatedTo = newManager
			return cfg
		})
		return contextWithConfig(c, newConfig)
	}
}

func (c *Ctx) decommission(ns string) {
	c.transformContext = func(c context.Context) context.Context {
		newConfig := replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
			ret := *cfg
			ret.Decommissioned = true
			return &ret
		})
		return contextWithConfig(c, newConfig)
	}
}

func (c *Ctx) setWaitForRepro(ns string, d time.Duration) {
	c.transformContext = func(c context.Context) context.Context {
		newConfig := replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
			ret := *cfg
			ret.WaitForRepro = d
			return &ret
		})
		return contextWithConfig(c, newConfig)
	}
}

// GET sends admin-authorized HTTP GET request to the app.
func (c *Ctx) GET(url string) ([]byte, error) {
	return c.AuthGET(AccessAdmin, url)
}

// AuthGET sends HTTP GET request to the app with the specified authorization.
func (c *Ctx) AuthGET(access AccessLevel, url string) ([]byte, error) {
	w, err := c.httpRequest("GET", url, "", access)
	if err != nil {
		return nil, err
	}
	return w.Body.Bytes(), nil
}

// POST sends admin-authorized HTTP POST requestd to the app.
func (c *Ctx) POST(url, body string) ([]byte, error) {
	w, err := c.httpRequest("POST", url, body, AccessAdmin)
	if err != nil {
		return nil, err
	}
	return w.Body.Bytes(), nil
}

// ContentType returns the response Content-Type header value.
func (c *Ctx) ContentType(url string) (string, error) {
	w, err := c.httpRequest("HEAD", url, "", AccessAdmin)
	if err != nil {
		return "", err
	}
	values := w.Header()["Content-Type"]
	if len(values) == 0 {
		return "", fmt.Errorf("no Content-Type")
	}
	return values[0], nil
}

func (c *Ctx) httpRequest(method, url, body string, access AccessLevel) (*httptest.ResponseRecorder, error) {
	c.t.Logf("%v: %v", method, url)
	r, err := c.inst.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	r.Header.Add("X-Appengine-User-IP", "127.0.0.1")
	r = registerRequest(r, c)
	r = r.WithContext(c.transformContext(r.Context()))
	if access == AccessAdmin || access == AccessUser {
		user := &user.User{
			Email:      "user@syzkaller.com",
			AuthDomain: "gmail.com",
		}
		if access == AccessAdmin {
			user.Admin = true
		}
		aetest.Login(user, r)
	}
	w := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(w, r)
	c.t.Logf("REPLY: %v", w.Code)
	if w.Code != http.StatusOK {
		return nil, &HTTPError{w.Code, w.Body.String(), w.Result().Header}
	}
	return w, nil
}

type HTTPError struct {
	Code    int
	Body    string
	Headers http.Header
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("%v: %v", err.Code, err.Body)
}

func (c *Ctx) loadBug(extID string) (*Bug, *Crash, *Build) {
	bug, _, err := findBugByReportingID(c.ctx, extID)
	if err != nil {
		c.t.Fatalf("failed to load bug: %v", err)
	}
	return c.loadBugInfo(bug)
}

func (c *Ctx) loadBugByHash(hash string) (*Bug, *Crash, *Build) {
	bug := new(Bug)
	bugKey := db.NewKey(c.ctx, "Bug", hash, 0, nil)
	c.expectOK(db.Get(c.ctx, bugKey, bug))
	return c.loadBugInfo(bug)
}

func (c *Ctx) loadBugInfo(bug *Bug) (*Bug, *Crash, *Build) {
	crash, _, err := findCrashForBug(c.ctx, bug)
	if err != nil {
		c.t.Fatalf("failed to load crash: %v", err)
	}
	build := c.loadBuild(bug.Namespace, crash.BuildID)
	return bug, crash, build
}

func (c *Ctx) loadJob(extID string) (*Job, *Build, *Crash) {
	jobKey, err := jobID2Key(c.ctx, extID)
	if err != nil {
		c.t.Fatalf("failed to create job key: %v", err)
	}
	job := new(Job)
	if err := db.Get(c.ctx, jobKey, job); err != nil {
		c.t.Fatalf("failed to get job %v: %v", extID, err)
	}
	build := c.loadBuild(job.Namespace, job.BuildID)
	crash := new(Crash)
	crashKey := db.NewKey(c.ctx, "Crash", "", job.CrashID, jobKey.Parent())
	if err := db.Get(c.ctx, crashKey, crash); err != nil {
		c.t.Fatalf("failed to load crash for job: %v", err)
	}
	return job, build, crash
}

func (c *Ctx) loadBuild(ns, id string) *Build {
	build, err := loadBuild(c.ctx, ns, id)
	c.expectOK(err)
	return build
}

func (c *Ctx) loadManager(ns, name string) (*Manager, *Build) {
	mgr, err := loadManager(c.ctx, ns, name)
	c.expectOK(err)
	build := c.loadBuild(ns, mgr.CurrentBuild)
	return mgr, build
}

func (c *Ctx) loadSingleBug() (*Bug, *db.Key) {
	var bugs []*Bug
	keys, err := db.NewQuery("Bug").GetAll(c.ctx, &bugs)
	c.expectEQ(err, nil)
	c.expectEQ(len(bugs), 1)

	return bugs[0], keys[0]
}

func (c *Ctx) loadSingleJob() (*Job, *db.Key) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").GetAll(c.ctx, &jobs)
	c.expectEQ(err, nil)
	c.expectEQ(len(jobs), 1)

	return jobs[0], keys[0]
}

func (c *Ctx) checkURLContents(url string, want []byte) {
	c.t.Helper()
	got, err := c.AuthGET(AccessAdmin, url)
	if err != nil {
		c.t.Fatalf("%v request failed: %v", url, err)
	}
	if !bytes.Equal(got, want) {
		c.t.Fatalf("url %v: got:\n%s\nwant:\n%s\n", url, got, want)
	}
}

func (c *Ctx) pollEmailBug() *aemail.Message {
	_, err := c.GET("/cron/email_poll")
	c.expectOK(err)
	if len(c.emailSink) == 0 {
		c.t.Helper()
		c.t.Fatal("got no emails")
	}
	return <-c.emailSink
}

func (c *Ctx) pollEmailExtID() string {
	c.t.Helper()
	_, extBugID := c.pollEmailAndExtID()
	return extBugID
}

func (c *Ctx) pollEmailAndExtID() (string, string) {
	c.t.Helper()
	msg := c.pollEmailBug()
	_, extBugID, err := email.RemoveAddrContext(msg.Sender)
	if err != nil {
		c.t.Fatalf("failed to remove addr context: %v", err)
	}
	return msg.Sender, extBugID
}

func (c *Ctx) expectNoEmail() {
	_, err := c.GET("/cron/email_poll")
	c.expectOK(err)
	if len(c.emailSink) != 0 {
		msg := <-c.emailSink
		c.t.Helper()
		c.t.Fatalf("got unexpected email: %v\n%s", msg.Subject, msg.Body)
	}
}

type apiClient struct {
	*Ctx
	*dashapi.Dashboard
}

func (c *Ctx) makeClient(client, key string, failOnErrors bool) *apiClient {
	doer := func(r *http.Request) (*http.Response, error) {
		r = registerRequest(r, c)
		r = r.WithContext(c.transformContext(r.Context()))
		w := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(w, r)
		res := &http.Response{
			StatusCode: w.Code,
			Status:     http.StatusText(w.Code),
			Body:       io.NopCloser(w.Result().Body),
		}
		return res, nil
	}
	logger := func(msg string, args ...interface{}) {
		c.t.Logf("%v: "+msg, append([]interface{}{caller(3)}, args...)...)
	}
	errorHandler := func(err error) {
		if failOnErrors {
			c.t.Fatalf("\n%v: %v", caller(2), err)
		}
	}
	dash, err := dashapi.NewCustom(client, "", key, c.inst.NewRequest, doer, logger, errorHandler)
	if err != nil {
		panic(fmt.Sprintf("Impossible error: %v", err))
	}
	return &apiClient{
		Ctx:       c,
		Dashboard: dash,
	}
}

func (client *apiClient) pollBugs(expect int) []*dashapi.BugReport {
	resp, _ := client.ReportingPollBugs("test")
	if len(resp.Reports) != expect {
		client.t.Helper()
		client.t.Fatalf("want %v reports, got %v", expect, len(resp.Reports))
	}
	for _, rep := range resp.Reports {
		reproLevel := dashapi.ReproLevelNone
		if len(rep.ReproC) != 0 {
			reproLevel = dashapi.ReproLevelC
		} else if len(rep.ReproSyz) != 0 {
			reproLevel = dashapi.ReproLevelSyz
		}
		reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
			ID:         rep.ID,
			JobID:      rep.JobID,
			Status:     dashapi.BugStatusOpen,
			ReproLevel: reproLevel,
			CrashID:    rep.CrashID,
		})
		client.expectEQ(reply.Error, false)
		client.expectEQ(reply.OK, true)
	}
	return resp.Reports
}

func (client *apiClient) pollBug() *dashapi.BugReport {
	return client.pollBugs(1)[0]
}

func (client *apiClient) pollNotifs(expect int) []*dashapi.BugNotification {
	resp, _ := client.ReportingPollNotifications("test")
	if len(resp.Notifications) != expect {
		client.t.Helper()
		client.t.Fatalf("want %v notifs, got %v", expect, len(resp.Notifications))
	}
	return resp.Notifications
}

func (client *apiClient) updateBug(extID string, status dashapi.BugStatus, dup string) {
	reply, _ := client.ReportingUpdate(&dashapi.BugUpdate{
		ID:     extID,
		Status: status,
		DupOf:  dup,
	})
	client.expectTrue(reply.OK)
}

func (client *apiClient) pollSpecificJobs(manager string, jobs dashapi.ManagerJobs) *dashapi.JobPollResp {
	req := &dashapi.JobPollReq{
		Managers: map[string]dashapi.ManagerJobs{
			manager: jobs,
		},
	}
	resp, err := client.JobPoll(req)
	client.expectOK(err)
	return resp
}

func (client *apiClient) pollJobs(manager string) *dashapi.JobPollResp {
	return client.pollSpecificJobs(manager, dashapi.ManagerJobs{
		TestPatches: true,
		BisectCause: true,
		BisectFix:   true,
	})
}

func (client *apiClient) pollAndFailBisectJob(manager string) {
	resp := client.pollJobs(manager)
	client.expectNE(resp.ID, "")
	client.expectEQ(resp.Type, dashapi.JobBisectCause)
	done := &dashapi.JobDoneReq{
		ID:    resp.ID,
		Error: []byte("pollAndFailBisectJob"),
	}
	client.expectOK(client.JobDone(done))
}

type (
	EmailOptMessageID int
	EmailOptSubject   string
	EmailOptFrom      string
	EmailOptOrigFrom  string
	EmailOptCC        []string
	EmailOptSender    string
)

func (c *Ctx) incomingEmail(to, body string, opts ...interface{}) {
	id := 0
	subject := "crash1"
	from := "default@sender.com"
	cc := []string{"test@syzkaller.com", "bugs@syzkaller.com", "bugs2@syzkaller.com"}
	sender := ""
	origFrom := ""
	for _, o := range opts {
		switch opt := o.(type) {
		case EmailOptMessageID:
			id = int(opt)
		case EmailOptSubject:
			subject = string(opt)
		case EmailOptFrom:
			from = string(opt)
		case EmailOptSender:
			sender = string(opt)
		case EmailOptCC:
			cc = []string(opt)
		case EmailOptOrigFrom:
			origFrom = fmt.Sprintf("\nX-Original-From: %v", string(opt))
		}
	}
	if sender == "" {
		sender = from
	}
	email := fmt.Sprintf(`Sender: %v
Date: Tue, 15 Aug 2017 14:59:00 -0700
Message-ID: <%v>
Subject: %v
From: %v
Cc: %v
To: %v%v
Content-Type: text/plain

%v
`, sender, id, subject, from, strings.Join(cc, ","), to, origFrom, body)
	log.Infof(c.ctx, "sending %s", email)
	_, err := c.POST("/_ah/mail/email@server.com", email)
	c.expectOK(err)
}

func initMocks() {
	// Mock time as some functionality relies on real time.
	timeNow = func(c context.Context) time.Time {
		return getRequestContext(c).mockedTime
	}
	sendEmail = func(c context.Context, msg *aemail.Message) error {
		getRequestContext(c).emailSink <- msg
		return nil
	}
	maxCrashes = func() int {
		// dev_appserver is very slow, so let's make tests smaller.
		const maxCrashesDuringTest = 20
		return maxCrashesDuringTest
	}
}

// Machinery to associate mocked time with requests.
type RequestMapping struct {
	id  int
	ctx *Ctx
}

var (
	requestMu       sync.Mutex
	requestNum      int
	requestContexts []RequestMapping
)

func registerRequest(r *http.Request, c *Ctx) *http.Request {
	requestMu.Lock()
	defer requestMu.Unlock()

	requestNum++
	newContext := context.WithValue(r.Context(), requestIDKey{}, requestNum)
	newRequest := r.WithContext(newContext)
	requestContexts = append(requestContexts, RequestMapping{requestNum, c})
	return newRequest
}

func getRequestContext(c context.Context) *Ctx {
	requestMu.Lock()
	defer requestMu.Unlock()
	reqID := getRequestID(c)
	for _, m := range requestContexts {
		if m.id == reqID {
			return m.ctx
		}
	}
	panic(fmt.Sprintf("no context for: %#v", c))
}

func unregisterContext(c *Ctx) {
	requestMu.Lock()
	defer requestMu.Unlock()
	n := 0
	for _, m := range requestContexts {
		if m.ctx == c {
			continue
		}
		requestContexts[n] = m
		n++
	}
	requestContexts = requestContexts[:n]
}

type requestIDKey struct{}

func getRequestID(c context.Context) int {
	val, ok := c.Value(requestIDKey{}).(int)
	if !ok {
		panic("the context did not come from a test")
	}
	return val
}

// Create a shallow copy of GlobalConfig with a replaced namespace config.
func replaceNamespaceConfig(c context.Context, ns string, f func(*Config) *Config) *GlobalConfig {
	ret := *getConfig(c)
	newNsMap := map[string]*Config{}
	for name, nsCfg := range ret.Namespaces {
		if name == ns {
			nsCfg = f(nsCfg)
		}
		newNsMap[name] = nsCfg
	}
	ret.Namespaces = newNsMap
	return &ret
}

func replaceManagerConfig(c context.Context, ns, mgr string, f func(ConfigManager) ConfigManager) *GlobalConfig {
	return replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
		ret := *cfg
		newMgrMap := map[string]ConfigManager{}
		for name, mgrCfg := range ret.Managers {
			if name == mgr {
				mgrCfg = f(mgrCfg)
			}
			newMgrMap[name] = mgrCfg
		}
		ret.Managers = newMgrMap
		return &ret
	})
}

func replaceReporting(c context.Context, ns, name string, f func(Reporting) Reporting) *GlobalConfig {
	return replaceNamespaceConfig(c, ns, func(cfg *Config) *Config {
		ret := *cfg
		var newReporting []Reporting
		for _, cfg := range ret.Reporting {
			if cfg.Name == name {
				cfg = f(cfg)
			}
			newReporting = append(newReporting, cfg)
		}
		ret.Reporting = newReporting
		return &ret
	})
}
