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
)

var (
	flagLocalUI     = flag.Bool("local-ui", false, "start local web server in the TestLocalUI test")
	flagLocalUIAddr = flag.String("local-ui-addr", "127.0.0.1:0", "run the web server on this network address")
	flagLocalUIUser = flag.String("local-ui-user", "admin", "authenticate requests as admin/user/none")
)

// Run the test with:
//
//	DOCKERARGS=-p=127.0.0.1:50556:50556 tools/syz-env go test -run TestLocalUI -timeout=0 -v ./dashboard/app \
//		-local-ui -local-ui-addr=:50556
//
// or if you have gcloud installed (faster, and opens the browser):
//
//	go test -run TestLocalUI -timeout=0 -v ./dashboard/app -local-ui
func TestLocalUI(t *testing.T) {
	if _, deadline := t.Deadline(); *flagLocalUI && (deadline || !testing.Verbose()) {
		t.Fatal("TestLocalUI should be run with -timeout=0 -v flags")
	}
	c := NewSpannerCtx(t)
	defer c.Close()
	c.transformContext = func(ctx context.Context) context.Context {
		return contextWithConfig(ctx, localUIConfig)
	}
	populateLocalUIDB(t, c)
	if !*flagLocalUI {
		return
	}
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
	Clients: map[string]APIClient{
		localUIGlobalClient: {Key: localUIGlobalPassword},
	},
	Namespaces: map[string]*Config{
		"linux": {
			DisplayTitle: "Linux",
			AccessLevel:  AccessPublic,
			AI:           &AIConfig{},
			Key:          password1,
			Clients: map[string]APIClient{
				localUIClient: {Key: localUIPassword},
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
	localUIClient         = "local_ui_client"
	localUIPassword       = "localuipasswordlocaluipasswordlocaluipassword"
	localUIGlobalClient   = "local_ui_global_client"
	localUIGlobalPassword = "localuiglobalpasswordlocaluiglobalpasswordlocaluiglobalpassword"
)

func populateLocalUIDB(t *testing.T, c *Ctx) {
	client := c.makeClient(localUIClient, localUIPassword, true)
	globalClient := c.makeClient(localUIGlobalClient, localUIGlobalPassword, true)
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
	c.advanceTime(24 * time.Hour)

	fixedBugs := []struct {
		Title  string
		Author string
		Commit string
	}{
		{
			Title:  "use-after-free in socket_close",
			Author: "Aidan Black <aidan@kernel.syz>",
			Commit: "net: fix use-after-free in socket_close",
		},
		{
			Title:  "slab-out-of-bounds in kfree",
			Author: "Balthazar White <balthazar@kernel.syz>",
			Commit: "mm: fix slab-out-of-bounds in kfree",
		},
		{
			Title:  "memory corruption in ext4_foo_bar",
			Author: "Cedric Green <cedric@kernel.syz>",
			Commit: "ext4: fix memory corruption in ext4_foo_bar",
		},
		{
			Title:  "stack overflow in io_uring",
			Author: "Doran Brown <doran@kernel.syz>",
			Commit: "io_uring: fix stack overflow",
		},
		{
			Title:  "memory leak in hub_probe",
			Author: "Elara Blue <elara@kernel.syz>",
			Commit: "usb: fix memory leak in hub_probe",
		},
	}

	for _, bug := range fixedBugs {
		client.ReportCrash(&dashapi.Crash{
			BuildID:  "build0",
			Title:    bug.Title,
			Report:   []byte("report"),
			ReproC:   []byte("int main() {}"),
			ReproSyz: []byte("syncfs"),
		})
	}

	for i := 0; i < 4; i++ {
		t.Logf("polling bugs iteration %v", i)
		respBugs, err := globalClient.ReportingPollBugs("email")
		if err != nil {
			t.Fatalf("ReportingPollBugs failed: %v", err)
		}
		if respBugs == nil || len(respBugs.Reports) == 0 {
			break
		}
		var fixCommits []dashapi.Commit
		for _, rep := range respBugs.Reports {
			isFixed := false
			for _, bug := range fixedBugs {
				if rep.Title == bug.Title {
					fixCommits = append(fixCommits, dashapi.Commit{
						Title:  bug.Commit,
						Author: bug.Author,
						BugIDs: []string{rep.ID},
					})
					isFixed = true
					break
				}
			}
			if !isFixed {
				t.Logf("acknowledging bug %q without fixing it", rep.Title)
				reproLevel := dashapi.ReproLevelNone
				if len(rep.ReproC) != 0 {
					reproLevel = dashapi.ReproLevelC
				} else if len(rep.ReproSyz) != 0 {
					reproLevel = dashapi.ReproLevelSyz
				}
				_, err := globalClient.ReportingUpdate(&dashapi.BugUpdate{
					ID:         rep.ID,
					Status:     dashapi.BugStatusOpen,
					ReproLevel: reproLevel,
				})
				if err != nil {
					t.Fatalf("ReportingUpdate failed for %q: %v", rep.Title, err)
				}
			}
		}
		if len(fixCommits) == 0 {
			continue
		}
		// Now upload a build that includes these fix commits for ALL managers.
		for buildID := 0; buildID < 3; buildID++ {
			err := client.UploadBuild(&dashapi.Build{
				Manager:           fmt.Sprintf("manager%v", buildID),
				ID:                fmt.Sprintf("build_fixing_%v_%v", i, buildID),
				OS:                targets.Linux,
				Arch:              targets.AMD64,
				VMArch:            targets.AMD64,
				SyzkallerCommit:   fmt.Sprintf("syzkaller_commit%v", buildID),
				CompilerID:        fmt.Sprintf("compiler%v", buildID),
				KernelRepo:        "repo0",
				KernelBranch:      "branch0",
				KernelCommit:      fmt.Sprintf("kernel_commit_fixing_%v_%v", i, buildID),
				KernelCommitTitle: fmt.Sprintf("kernel_commit_title_fixing_%v_%v", i, buildID),
				KernelCommitDate:  timeNow(c.ctx),
				KernelConfig:      []byte("config"),
				FixCommits:        fixCommits,
			})
			if err != nil {
				t.Fatalf("UploadBuild failed: %v", err)
			}
		}
	}
	t.Logf("done populating DB")
	resp, _ := globalClient.AIJobPoll(&dashapi.AIJobPollReq{
		CodeRevision: "xxx",
		Workflows: []dashapi.AIWorkflow{
			{Type: ai.WorkflowPatching, Name: string(ai.WorkflowPatching)},
			{Type: ai.WorkflowModeration, Name: string(ai.WorkflowModeration)},
			{Type: ai.WorkflowAssessmentKCSAN, Name: string(ai.WorkflowAssessmentKCSAN)},
		},
	})
	seq := 1
	ts := c.mockedTime
	globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
			globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
			globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
			globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
		globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
	globalClient.AITrajectoryLog(&dashapi.AITrajectoryReq{
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
	globalClient.AIJobDone(&dashapi.AIJobDoneReq{
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
