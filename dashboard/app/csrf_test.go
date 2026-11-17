// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/appengine/v2/aetest"
	db "google.golang.org/appengine/v2/datastore"
)

func TestCSRFTokenValidation(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// The helper flushes memcache as an admin that presents the given CSRF token.
	flush := func(token string) error {
		_, err := c.AuthPOSTForm(AccessAdmin, "/admin", url.Values{
			csrfFormField: {token},
			"action":      {"memcache_flush"},
		})
		return err
	}
	// The helper returns an admin token issued at the given offset from the current time.
	signAt := func(offset time.Duration) string {
		secret := []byte(getConfig(c.ctx).CSRFSecret)
		ts := strconv.FormatInt(c.mockedTime.Add(offset).Unix(), 10)
		mac := computeCSRFMAC(secret, makeUser(AuthorizedAdmin).Email, ts)
		return ts + ":" + base64.RawURLEncoding.EncodeToString(mac)
	}
	now := strconv.FormatInt(c.mockedTime.Unix(), 10)

	for _, bad := range []string{
		"",
		"not-a-valid-token",
		"abc:def",
		now + ":!!!not-base64!!!",
		now + ":" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		// The token is bound to another user.
		c.csrfToken(AccessUser),
		// The token is issued too far in the future.
		signAt(csrfClockSkew + time.Minute),
	} {
		t.Logf("bad token: %q", bad)
		expectFailureStatus(t, flush(bad), http.StatusForbidden)
	}
	// Slight clock skew across GAE instances is tolerated.
	require.NoError(t, flush(signAt(time.Minute)))

	// Signed-in ACL user with AccessPublic must never receive a CSRF token.
	r := c.newTestRequest(http.MethodGet, "/", "", AccessPublic)
	aetest.Login(makeUser(AuthorizedAccessPublic), r)
	pubACLToken := generateCSRFToken(r.Context())
	assert.Empty(t, pubACLToken)

	// Valid token passed only in URL query string must be rejected.
	adminToken := c.csrfToken(AccessAdmin)
	_, err := c.httpRequest(http.MethodPost, "/admin?"+csrfFormField+"="+url.QueryEscape(adminToken),
		"action=memcache_flush", "application/x-www-form-urlencoded", AccessAdmin)
	expectFailureStatus(t, err, http.StatusForbidden)

	// Token survives memcache_flush because the signing key comes from GlobalConfig.
	require.NoError(t, flush(adminToken))
	require.NoError(t, flush(adminToken))

	// Expired token (> 24h) is rejected.
	c.advanceTime(csrfTokenTTL + time.Minute)
	expectFailureStatus(t, flush(adminToken), http.StatusForbidden)

	// Empty or too-short CSRFSecret fails config validation.
	for _, secret := range []string{"", "too-short"} {
		cfg := &GlobalConfig{
			DefaultNamespace: "ns",
			DungeonNamespace: "ns",
			Namespaces:       map[string]*Config{"ns": {}},
			CSRFSecret:       secret,
		}
		assert.PanicsWithValue(t, fmt.Sprintf("CSRFSecret must be at least %d bytes", csrfMinSecretLen),
			func() { checkConfig(cfg) })
	}
}

func TestCrossOriginAndMethodProtection(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	_, err := c.httpRequest(http.MethodPut, "/admin", "", "", AccessAdmin)
	expectFailureStatus(t, err, http.StatusMethodNotAllowed)

	// The requests carry a valid token, so only the cross-origin checks decide.
	form := url.Values{
		csrfFormField: {c.csrfToken(AccessAdmin)},
		"action":      {"memcache_flush"},
	}.Encode()
	post := func(header, value string) error {
		_, err := c.httpRequestWithHeaders(http.MethodPost, "/admin", form,
			"application/x-www-form-urlencoded", AccessAdmin, map[string]string{header: value})
		return err
	}
	expectFailureStatus(t, post("Sec-Fetch-Site", "cross-site"), http.StatusForbidden)
	expectFailureStatus(t, post("Sec-Fetch-Site", "same-site"), http.StatusForbidden)
	// Origin is the fallback when Sec-Fetch-Site is absent.
	expectFailureStatus(t, post("Origin", "https://evil.example"), http.StatusForbidden)
	require.NoError(t, post("Sec-Fetch-Site", "same-origin"))
}

func TestCSRFAdminAndBisectionInvalidation(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	build, _ := addBuildAndCrash(c)
	addBisectCauseJob(c, build)
	_, bugKey := c.loadSingleBug()
	job, jobKey := c.loadSingleJob()
	require.Empty(t, job.InvalidatedBy)

	// GET requests to /admin actions must fail and leave state untouched.
	_, err := c.AuthGET(AccessAdmin, "/admin?action=invalidate_bisection&key="+jobKey.Encode())
	expectFailureStatus(t, err, http.StatusMethodNotAllowed)
	job, _ = c.loadSingleJob()
	assert.Empty(t, job.InvalidatedBy)

	// Action passed only in URL query string on a CSRF-valid POST must also be rejected.
	_, err = c.AuthPOSTForm(AccessAdmin, "/admin?action=emergency_stop", url.Values{})
	expectFailureStatus(t, err, http.StatusBadRequest)
	stopped, err := emergentlyStopped(c.ctx)
	require.NoError(t, err)
	assert.False(t, stopped)

	// Keys that are not a Job key must be rejected.
	for _, badKey := range []*db.Key{
		bugKey,
		db.NewKey(c.ctx, "Job", "", 1, nil),
	} {
		_, err = c.AuthPOSTForm(AccessAdmin, "/admin", url.Values{
			"action": {"invalidate_bisection"},
			"key":    {badKey.Encode()},
		})
		expectFailureStatus(t, err, http.StatusBadRequest)
	}

	// Admin previewing a public bug with ?access=public must not see admin invalidation forms.
	pubBuild := testBuild(2)
	c.publicClient.UploadBuild(pubBuild)
	pubCrash := testCrashWithRepro(pubBuild, 2)
	c.publicClient.ReportCrash(pubCrash)
	pubExtID := c.publicClient.pollEmailExtID()
	pubBug, _, _ := c.loadBug(pubExtID)
	addBisectCauseJob(c, pubBuild)
	pubBugURL := bugLink(pubBug.keyHash(c.ctx))

	adminPubBugPage, err := c.GET(pubBugURL)
	require.NoError(t, err)
	assert.Contains(t, string(adminPubBugPage), "invalidate_bisection")

	pubPreview, err := c.GET(pubBugURL + "&access=public")
	require.NoError(t, err)
	assert.NotContains(t, string(pubPreview), "invalidate_bisection")
	assert.Empty(t, csrfInputRe.FindSubmatch(pubPreview))

	// Anonymous users don't get CSRF tokens either.
	anonPage, err := c.AuthGET(AccessPublic, "/access-public-email")
	require.NoError(t, err)
	assert.Empty(t, csrfInputRe.FindSubmatch(anonPage))

	// The per-job token rendered on the bug page allows to invalidate the bisection.
	bugPage, err := c.GET(bugLink(bugKey.StringID()))
	require.NoError(t, err)
	_, err = c.AuthPOSTForm(AccessAdmin, "/admin", url.Values{
		csrfFormField: {extractCSRFToken(t, bugPage)},
		"action":      {"invalidate_bisection"},
		"key":         {jobKey.Encode()},
	})
	expectFailureStatus(t, err, http.StatusFound)
	require.NoError(t, db.Get(c.ctx, jobKey, job))
	assert.Equal(t, makeUser(AuthorizedAdmin).Email, job.InvalidatedBy)

	// The page header token allows the 2-step emergency stop.
	adminStopPage, err := c.GET("/admin?stop_clicked=1")
	require.NoError(t, err)
	_, err = c.AuthPOSTForm(AccessAdmin, "/admin", url.Values{
		csrfFormField: {extractCSRFToken(t, adminStopPage)},
		"action":      {"emergency_stop"},
	})
	require.NoError(t, err)
	stopped, err = emergentlyStopped(c.ctx)
	require.NoError(t, err)
	assert.True(t, stopped)

	// The manager page rejects send-repro on GET, as it used to save the repro request.
	mgrBuild := testBuild(3)
	c.publicClient.UploadBuild(mgrBuild)
	_, err = c.AuthGET(AccessUser, "/access-public-email/manager/"+mgrBuild.Manager+"?send-repro=forged")
	expectFailureStatus(t, err, http.StatusMethodNotAllowed)
	reproResp, err := c.publicClient.LogToRepro(&dashapi.LogToReproReq{BuildID: mgrBuild.ID})
	require.NoError(t, err)
	assert.Empty(t, reproResp.CrashLog)
}

// TestCSRFAIEndpoints checks that GET requests with mutating parameters change nothing.
func TestCSRFAIEndpoints(t *testing.T) {
	c := NewSpannerCtx(t)
	defer c.Close()

	build := testBuild(1)
	c.aiClient.UploadBuild(build)
	crash := testCrashWithRepro(build, 1)
	c.aiClient.ReportCrash(crash)
	extID := c.aiClient.pollEmailExtID()
	bug, _, _ := c.loadBug(extID)
	// Each poll replaces the set of workflows that the agent supports, so always poll for both.
	patching := dashapi.AIWorkflow{Type: "patching", Name: "patching"}
	reproC := dashapi.AIWorkflow{Type: "repro-c", Name: "repro-c"}
	expectNoJob := func() {
		t.Helper()
		assert.Empty(t, c.pollAIJob(t, "agent-name", patching, reproC).ID)
	}
	expectNoJob()

	bugURL := bugLink(bug.keyHash(c.ctx))
	_, err := c.AuthGET(AccessUser, bugURL+"&ai-job-create=patching")
	require.NoError(t, err)
	expectNoJob()

	// These are all the fields that a successful POST needs.
	_, err = c.AuthGET(AccessUser, "/ains/ai?"+url.Values{
		"ai-job-create":       {"repro-c"},
		"BugDescription":      {"test bug desc"},
		"KernelRepo":          {"repo1"},
		"KernelCommit":        {"1111111111111111111111111111111111111111"},
		"TargetArch":          {"amd64"},
		"KernelConfigManager": {build.Manager},
	}.Encode())
	require.NoError(t, err)
	expectNoJob()

	_, err = c.AuthPOSTForm(AccessUser, bugURL, url.Values{"ai-job-create": {"patching"}})
	require.NoError(t, err)
	polled := c.pollAIJob(t, "agent-name", patching)
	require.NotEmpty(t, polled.ID)
	require.NoError(t, c.globalClient.AIJobDone(&dashapi.AIJobDoneReq{
		ID:      polled.ID,
		Results: map[string]any{"PatchDiff": "diff", "PatchDescription": "subj\n\nbody"},
	}))
	jobURL := fmt.Sprintf("/ai_job?id=%v", polled.ID)
	_, err = c.AuthGET(AccessUser, jobURL+"&action=set_correctness&correct="+url.QueryEscape(aiCorrectnessCorrect))
	require.NoError(t, err)
	dbJob, err := aidb.LoadJob(c.ctx, polled.ID)
	require.NoError(t, err)
	assert.NotEqual(t, aiCorrectnessCorrect, makeUIAIJob(dbJob).Correct)

	// /{ns}/ai serializes the whole page with the header into JSON, so it must not leak the token.
	aiJobsPage, err := c.AuthGET(AccessUser, "/ains/ai")
	require.NoError(t, err)
	aiJSON, err := c.AuthGET(AccessUser, "/ains/ai?json=1")
	require.NoError(t, err)
	assert.NotContains(t, string(aiJSON), "CSRFToken")
	assert.NotContains(t, string(aiJSON), extractCSRFToken(t, aiJobsPage))
}

var csrfInputRe = regexp.MustCompile(`<input[^>]*name="` + csrfFormField + `"[^>]*value="([^"]*)"`)

func extractCSRFToken(t *testing.T, page []byte) string {
	t.Helper()
	m := csrfInputRe.FindSubmatch(page)
	require.Len(t, m, 2, "expected %s hidden input in page", csrfFormField)
	require.NotEmpty(t, m[1])
	return string(m[1])
}
