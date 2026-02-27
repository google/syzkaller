// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/stretchr/testify/require"
)

// Example command:
// DOCKERARGS="-p 8081:8081" ./tools/syz-env go test -v ./syz-cluster/dashboard -run TestLocalUI \
//	-local-ui -local-ui-addr=:8081 -timeout=0
// Then in the browser:
// http://localhost:8081

var (
	flagLocalUI     = flag.Bool("local-ui", false, "start local web server in the TestLocalUI test")
	flagLocalUIAddr = flag.String("local-ui-addr", "127.0.0.1:8081", "run the web server on this network address")
)

func TestLocalUI(t *testing.T) {
	if !*flagLocalUI {
		t.Skip("local UI wasn't requested with -local-ui flag")
	}
	if _, deadline := t.Deadline(); deadline || !testing.Verbose() {
		t.Fatal("TestLocalUI should be run with -timeout=0 -v flags")
	}

	env, ctx := app.TestEnvironment(t)
	// This spins up a separate API server that shares the same database (env.Spanner).
	// We use it to populate the database.
	client := controller.TestServer(t, env)

	// Populate database with some data.
	populateData(t, ctx, client, env)

	handler, err := newHandler(env)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", *flagLocalUIAddr)
	require.NoError(t, err)

	t.Logf("serving dashboard at http://%s", ln.Addr())
	log.Printf("serving dashboard at http://%s", ln.Addr())

	// Block until the test is killed.
	err = http.Serve(ln, handler.Mux())
	require.NoError(t, err)
}

func populateData(t *testing.T, ctx context.Context, client *api.Client, env *app.AppEnvironment) {
	series := controller.DummySeries()
	series.PublishedAt = time.Now()
	series.AuthorEmail = "fake@author.com"
	series.Cc = []string{"fake@cc.com", "another@cc.com"}
	ids := controller.UploadTestSeries(t, ctx, client, series)

	// Add a fake triage log.
	uri, err := env.BlobStorage.Write(bytes.NewReader([]byte("fake triage log")), "triage-log")
	require.NoError(t, err)
	sessionRepo := db.NewSessionRepository(env.Spanner)
	err = sessionRepo.Update(ctx, ids.SessionID, func(s *db.Session) error {
		s.TriageLogURI = uri
		return nil
	})
	require.NoError(t, err)

	build := controller.DummyBuild()
	buildResp := controller.UploadTestBuild(t, ctx, client, build)

	// Upload a test result (Running)
	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test_running",
		Result:      api.TestRunning,
		Log:         []byte("running log"),
	})
	require.NoError(t, err)

	// Upload a test result (Failed)
	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test_failed",
		Result:      api.TestFailed,
		Log:         []byte("failed log"),
	})
	require.NoError(t, err)

	// Upload findings.
	findings := controller.DummyFindings()
	for _, finding := range findings {
		finding.SessionID = ids.SessionID
		finding.TestName = "test_failed"
		err = client.UploadFinding(ctx, finding)
		require.NoError(t, err)
	}

	// Upload test steps.
	err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
		TestName: "test_failed",
		Title:    "crash in foo",
		Result:   api.StepResultPassed,
		Target:   api.StepTargetBase,
		Log:      []byte("base log"),
	})
	require.NoError(t, err)

	err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
		TestName: "test_failed",
		Title:    "crash in foo",
		Result:   api.StepResultFailed,
		Target:   api.StepTargetPatched,
		Log:      []byte("patched log"),
	})
	require.NoError(t, err)

	// Upload a test result (Complex Steps)
	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test_complex",
		Result:      api.TestPassed,
		Log:         []byte("complex log"),
	})
	require.NoError(t, err)

	// Upload test steps for complex test.
	limit := 5
	for i := 0; i < limit; i++ {
		title := "crash in loop " + string(rune('A'+i))
		// Base passed.
		err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
			TestName: "test_complex",
			Title:    title,
			Result:   api.StepResultPassed,
			Target:   api.StepTargetBase,
			Log:      []byte("base log " + title),
		})
		require.NoError(t, err)

		// Patched passed too.
		err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
			TestName: "test_complex",
			Title:    title,
			Result:   api.StepResultPassed,
			Target:   api.StepTargetPatched,
			Log:      []byte("patched log " + title),
		})
		require.NoError(t, err)
	}

	// Upload a test result (Error Step)
	err = client.UploadSessionTest(ctx, &api.SessionTest{
		SessionID:   ids.SessionID,
		BaseBuildID: buildResp.ID,
		TestName:    "test_error",
		Result:      api.TestFailed,
		Log:         []byte("error log"),
	})
	require.NoError(t, err)

	err = client.UploadTestStep(ctx, ids.SessionID, &api.SessionTestStep{
		TestName: "test_error",
		Title:    "crash in bar",
		Result:   api.StepResultError,
		Target:   api.StepTargetBase,
		Log:      []byte("base error log"),
	})
	require.NoError(t, err)
}
