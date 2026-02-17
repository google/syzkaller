// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
	"google.golang.org/appengine/v2/aetest"
	db "google.golang.org/appengine/v2/datastore"
)

var (
	flagLocalUI     = flag.Bool("local-ui", false, "start local web server in the TestLocalUI test")
	flagLocalUIAddr = flag.String("local-ui-addr", "127.0.0.1:0", "run the web server on this network address")
	flagLocalUIUser = flag.String("local-ui-user", "admin", "authenticate requests as admin/user/none")
)

// Run the test with:
//
//	DOCKERARGS=-p=50556:50556 tools/syz-env go test -run TestLocalUI -timeout=0 -v ./dashboard/app \
//		-local-ui -local-ui-addr=:50556
//
// or if you have gcloud installed (faster, and opens the browser):
//
//	go test -run TestLocalUI -timeout=0 -v ./dashboard/app -local-ui
func TestLocalUI(t *testing.T) {
	if !*flagLocalUI {
		t.Skip("local UI wasn't requested with -local-ui flag")
	}
	if _, deadline := t.Deadline(); deadline || !testing.Verbose() {
		t.Fatal("TestLocalUI should be run with -timeout=0 -v flags")
	}
	c := NewSpannerCtx(t)
	defer c.Close()
	checkConfig(localUIConfig)
	c.transformContext = func(ctx context.Context) context.Context {
		return contextWithConfig(ctx, localUIConfig)
	}
	populateLocalUIDB(t, c)
	ln, err := net.Listen("tcp4", *flagLocalUIAddr)
	require.NoError(t, err)
	url := fmt.Sprintf("http://%v", ln.Addr())
	exec.Command("xdg-open", url+"/linux").Start()
	go func() {
		// Let the dev_appserver print tons of unuseful garbage to the console
		// before we print the serving address, so it's possible to find it in all the garbage.
		time.Sleep(3 * time.Second)
		t.Logf("serving http on %v", url)
	}()
	require.NoError(t, http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.String()
		if file := filepath.Join(".", url); url != "/" && (osutil.IsExist(file) || url == "/favicon.ico") {
			http.ServeFile(w, r, file)
			return
		}
		t.Logf("request: %v", url)
		req, err := c.inst.NewRequest(r.Method, url, r.Body)
		require.NoError(t, err)
		req.Header = r.Header
		req.Header.Add("X-Appengine-User-IP", "127.0.0.1")
		req = req.WithContext(c.transformContext(req.Context()))
		req = registerRequest(req, c)
		switch *flagLocalUIUser {
		case "admin":
			aetest.Login(makeUser(AuthorizedAdmin), req)
		case "user":
			aetest.Login(makeUser(AuthorizedUser), req)
		}
		http.DefaultServeMux.ServeHTTP(w, req)
	})))
}

var localUIConfig = &GlobalConfig{
	AccessLevel:      AccessPublic,
	DefaultNamespace: "linux",
	Namespaces: map[string]*Config{
		"linux": {
			DisplayTitle: "Linux",
			AccessLevel:  AccessPublic,
			AI:           true,
			Key:          password1,
			Clients: map[string]string{
				localUIClient: localUIPassword,
			},
			Repos: []KernelRepo{
				{
					URL:    "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
					Branch: "master",
					Alias:  "upstream",
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessPublic,
					Name:        "email-reporting",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:            "test@syzkaller.com",
						HandleListEmails: true,
						SubjectPrefix:    "[syzbot]",
					},
				},
			},
		},
	},
}

const (
	localUIClient   = "local_ui_client"
	localUIPassword = "localuipasswordlocaluipasswordlocaluipassword"
)

func populateLocalUIDB(t *testing.T, c *Ctx) {
	client := c.makeClient(localUIClient, localUIPassword, true)
	bugTitles := []string{
		"KASAN: slab-use-after-free Write in nr_neigh_put",
		"KCSAN: data-race in mISDN_ioctl / mISDN_read",
		"WARNING in raw_ioctl",
	}
	for buildID := 0; buildID < 3; buildID++ {
		build := &dashapi.Build{
			Manager:           fmt.Sprintf("manager%v", buildID),
			ID:                fmt.Sprintf("build%v", buildID),
			OS:                targets.Linux,
			Arch:              targets.AMD64,
			VMArch:            targets.AMD64,
			SyzkallerCommit:   fmt.Sprintf("syzkaller_commit%v", buildID),
			CompilerID:        fmt.Sprintf("compiler%v", buildID),
			KernelRepo:        fmt.Sprintf("repo%v", buildID),
			KernelBranch:      fmt.Sprintf("branch%v", buildID),
			KernelCommit:      strings.Repeat(fmt.Sprint(buildID), 40)[:40],
			KernelCommitTitle: fmt.Sprintf("kernel_commit_title%v", buildID),
			KernelCommitDate:  time.Date(1, 2, 3, 4, 5, 6, 0, time.UTC),
			KernelConfig:      []byte(fmt.Sprintf("config%v", buildID)),
		}
		client.UploadBuild(build)
		for bugID := 0; bugID < len(bugTitles); bugID++ {
			for crashID := 0; crashID < 3; crashID++ {
				client.ReportCrash(&dashapi.Crash{
					BuildID:     build.ID,
					Title:       bugTitles[bugID],
					Log:         []byte(fmt.Sprintf("log %v %v", bugID, crashID)),
					Report:      []byte(fmt.Sprintf("report %v %v", bugID, crashID)),
					MachineInfo: []byte(fmt.Sprintf("machine info %v %v", bugID, crashID)),
					ReproOpts:   []byte(fmt.Sprintf("repro opts %v %v", bugID, crashID)),
					ReproSyz:    []byte(fmt.Sprintf("syncfs %v %v", bugID, crashID)),
					ReproC:      []byte(fmt.Sprintf("int main() { return %v %v; }", bugID, crashID)),
					ReproLog:    []byte(fmt.Sprintf("repro log %v %v", bugID, crashID)),
				})
			}
		}
	}
	fixedBugs := []struct {
		Title      string
		Author     string
		Crashes    int64
		DaysToFix  int
		ReproLevel dashapi.ReproLevel
	}{
		{
			Title:      "net: use-after-free in socket_close",
			Author:     "Aidan Black <aidan@kernel.syz>",
			Crashes:    1200,
			DaysToFix:  2,
			ReproLevel: dashapi.ReproLevelC,
		},
		{
			Title:      "mm: slab-out-of-bounds in kfree",
			Author:     "Balthazar White <balthazar@kernel.syz>",
			Crashes:    550,
			DaysToFix:  5,
			ReproLevel: dashapi.ReproLevelSyz,
		},
		{
			Title:      "fs: scary data corruption",
			Author:     "Cedric Green <cedric@kernel.syz>",
			Crashes:    100,
			DaysToFix:  0,
			ReproLevel: dashapi.ReproLevelNone,
		},
		{
			Title:      "security: stack overflow in io_uring",
			Author:     "Doran Brown <doran@kernel.syz>",
			Crashes:    5000,
			DaysToFix:  400,
			ReproLevel: dashapi.ReproLevelC,
		},
		{
			Title:      "drivers/usb: memory leak in hub_probe",
			Author:     "Elara Blue <elara@kernel.syz>",
			Crashes:    150,
			DaysToFix:  10,
			ReproLevel: dashapi.ReproLevelSyz,
		},
	}
	for i, fb := range fixedBugs {
		buildID := fmt.Sprintf("fixed-build-%d", i)
		client.UploadBuild(&dashapi.Build{
			Manager:           "manager0",
			ID:                buildID,
			OS:                targets.Linux,
			Arch:              targets.AMD64,
			VMArch:            targets.AMD64,
			KernelRepo:        "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			KernelBranch:      "master",
			KernelCommit:      fmt.Sprintf("fixed_commit%d", i),
			KernelCommitTitle: "kernel commit",
			SyzkallerCommit:   fmt.Sprintf("syzkaller_commit%d", i),
			CompilerID:        "compiler0",
			KernelConfig:      []byte("config"),
		})

		crash := &dashapi.Crash{
			BuildID: buildID,
			Title:   fb.Title,
			Log:     []byte("log"),
			Report:  []byte("report"),
		}
		switch fb.ReproLevel {
		case dashapi.ReproLevelC:
			crash.ReproC = []byte("int main() {}")
		case dashapi.ReproLevelSyz:
			crash.ReproSyz = []byte("sync")
		}
		client.ReportCrash(crash)

		// Manual Datastore update to mark as Fixed.
		var bugs []*Bug
		keys, err := db.NewQuery("Bug").Filter("Title=", fb.Title).GetAll(c.ctx, &bugs)
		require.NoError(t, err)
		if len(bugs) == 0 {
			t.Fatalf("failed to find bug: %v", fb.Title)
		}
		bug := bugs[0]
		bug.Status = BugStatusFixed
		bug.NumCrashes = fb.Crashes
		bug.ReproLevel = fb.ReproLevel
		// Set dates to match DaysToFix.
		bug.Closed = time.Now()
		bug.FirstTime = bug.Closed.AddDate(0, 0, -fb.DaysToFix)
		if fb.DaysToFix == 0 {
			bug.FirstTime = bug.Closed.Add(-1 * time.Hour) // Fixed within an hour.
		}
		bug.Commits = []string{"fix: " + fb.Title}
		bug.CommitInfo = []Commit{
			{
				Title:  "fix: " + fb.Title,
				Author: fb.Author,
				Date:   bug.Closed,
			},
		}
		_, err = db.Put(c.ctx, keys[0], bug)
		require.NoError(t, err)
	}

	resp, _ := client.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: "xxx",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: string(ai.WorkflowPatching)},
			{Type: ai.WorkflowModeration, Name: string(ai.WorkflowModeration)},
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
		},
	})
	seq := 1
	ts := c.mockedTime
	client.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:      seq,
			Nesting:  1,
			Type:     trajectory.SpanAction,
			Name:     "test-action",
			Started:  tickRandom(&ts),
			Finished: ts,
		},
	})
	seq++
	for agentID := 1; agentID <= 3; agentID++ {
		agentName := fmt.Sprintf("agent-%d", agentID)
		agentStart := ts
		agentSeq := seq
		seq++
		for llmCall := 1; llmCall <= 3; llmCall++ {
			client.AITrajectoryLog(&dashapi.AITrajectoryReq{
				JobID: resp.ID,
				Span: &trajectory.Span{
					Seq:                  seq,
					Nesting:              2,
					Type:                 trajectory.SpanLLM,
					Name:                 agentName,
					Started:              tickRandom(&ts),
					Finished:             ts,
					InputTokens:          rand.IntN(1000),
					OutputTokens:         rand.IntN(100),
					OutputThoughtsTokens: rand.IntN(100),
				},
			})
			seq++
			client.AITrajectoryLog(&dashapi.AITrajectoryReq{
				JobID: resp.ID,
				Span: &trajectory.Span{
					Seq:      seq,
					Nesting:  2,
					Type:     trajectory.SpanTool,
					Name:     "tool-1",
					Started:  tickRandom(&ts),
					Finished: ts,
				},
			})
			seq++
			client.AITrajectoryLog(&dashapi.AITrajectoryReq{
				JobID: resp.ID,
				Span: &trajectory.Span{
					Seq:      seq,
					Nesting:  2,
					Type:     trajectory.SpanTool,
					Name:     "tool-2",
					Started:  tickRandom(&ts),
					Finished: ts,
				},
			})
			seq++
		}
		client.AITrajectoryLog(&dashapi.AITrajectoryReq{
			JobID: resp.ID,
			Span: &trajectory.Span{
				Seq:      agentSeq,
				Nesting:  1,
				Type:     trajectory.SpanAgent,
				Name:     agentName,
				Started:  agentStart,
				Finished: ts,
			},
		})
	}
	client.AITrajectoryLog(&dashapi.AITrajectoryReq{
		JobID: resp.ID,
		Span: &trajectory.Span{
			Seq:      0,
			Nesting:  0,
			Type:     trajectory.SpanFlow,
			Name:     "test-flow",
			Started:  c.mockedTime,
			Finished: ts,
		},
	})
	client.AIJobDone(&dashapi.AIJobDoneReq{
		ID: resp.ID,
		Results: map[string]any{
			"Benign":      false,
			"Confident":   true,
			"Explanation": "ISO C says data races result in undefined program behavior.",
		},
	})
}

// Advance the timer with random duration. Return the (copied) old time.
func tickRandom(t *time.Time) time.Time {
	oldTime := *t
	*t = t.Add(time.Duration(rand.IntN(10)+1) * time.Minute)
	return oldTime
}
