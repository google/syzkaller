package main

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/stretchr/testify/require"
)

func TestAIRender(t *testing.T) {
	// Mock specific data for nested flows
	// We want to simulate a flow that calls a sub-agent, which calls another sub-agent.

	now := time.Now()

	// Construct the trajectory as a forest (list of trees)
	trajectory := []*uiAITrajectoryNode{
		{
			uiAITrajectorySpan: &uiAITrajectorySpan{
				Seq:      1,
				Nesting:  0,
				Type:     "flow",
				Name:     "Root Flow",
				Started:  now.Add(-10 * time.Second),
				Duration: 10 * time.Second,
			},
			Children: []*uiAITrajectoryNode{
				{
					uiAITrajectorySpan: &uiAITrajectorySpan{
						Seq:      2,
						Nesting:  1,
						Type:     "agent",
						Name:     "Coordinator Agent",
						Started:  now.Add(-9 * time.Second),
						Duration: 8 * time.Second,
						Prompt:   "Coordinate the task",
						Reply:    "Task coordinated",
					},
					Children: []*uiAITrajectoryNode{
						{
							uiAITrajectorySpan: &uiAITrajectorySpan{
								Seq:      3,
								Nesting:  2,
								Type:     "tool",
								Name:     "Search",
								Started:  now.Add(-8 * time.Second),
								Duration: 1 * time.Second,
								Args: ` {
									"query": "syzkaller",
									"options": {
										"verbose": true,
										"filters": ["linux", "kernel", "fuzzing"],
										"advanced": {
											"depth": 5,
											"strategy": "recursive",
											"empty_check": "",
											"meta": {
												"author": "dmnk",
												"timestamp": 1234567890
											}
										}
									}
								}`,
								Results: `{"count": 100, "empty_result": ""}`,
							},
						},
						{
							uiAITrajectorySpan: &uiAITrajectorySpan{
								Seq:      4,
								Nesting:  2,
								Type:     "flow",
								Name:     "Sub Flow (Analysis)",
								Started:  now.Add(-6 * time.Second),
								Duration: 4 * time.Second,
							},
							Children: []*uiAITrajectoryNode{
								{
									uiAITrajectorySpan: &uiAITrajectorySpan{
										Seq:      5,
										Nesting:  3,
										Type:     "agent",
										Name:     "Analyzer Agent",
										Started:  now.Add(-5 * time.Second),
										Duration: 2 * time.Second,
										Thoughts: "Analyzing the crash dump...",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	page := &uiAIJobPage{
		Header: &uiHeader{Namespace: "test-ns", BugCounts: &CachedBugStats{}},
		Job: &uiAIJob{
			ID:      "test-job-id",
			Correct: "❓",
		},
		Trajectory:  trajectory,
		CrashReport: template.HTML("Crash report content"),
	}

	// Create output file in a known location for manual inspection.
	outDir := "/tmp/syzkaller_ai_test"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(outDir, "ai_job_render.html")
	f, err := os.Create(outFile)
	require.NoError(t, err)
	defer f.Close()

	// We need to use valid template paths.
	// Since we are running the test from dashboard/app, strict paths might be needed?
	// The templates variable uses glob search path.
	// In test environment, current directory is dashboard/app.
	// We might need to make sure pkg/html can find the templates.
	// Usually dashboard/app tests assume templates are in templates/ (local dir) or similar.
	// Let's assume templates are loaded correctly if we use the main package's 'templates' var.
	// However, 'templates' var initialization might fail if it can't find files.
	// We might need to fix GlobSearchPath if it defaults incorrectly.
	// pkg/html defaults to "templates/" for non-appengine.
	// if CWD is dashboard/app, then templates/ is right there.

	err = templates.ExecuteTemplate(f, "ai_job.html", page)
	require.NoError(t, err)

	t.Logf("rendered template to: %s", outFile)

	// Also write to a persistent location for verification.
	persistentFile := "ai_job_debug.html"
	pf, err := os.Create(persistentFile)
	require.NoError(t, err)
	defer pf.Close()
	templates.ExecuteTemplate(pf, "ai_job.html", page)

	// Read back and verify output file.
	content, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Contains(t, string(content), "node-1-root-flow",
		"Output should contain slugified ID for Root Flow")
	require.Contains(t, string(content), "node-2-coordinator-agent",
		"Output should contain slugified ID for Coordinator Agent")
	require.Contains(t, string(content), `<span class="json-empty">empty</span>`,
		"Output should contain styled empty string in Args")
	// We added empty_result to Results, so we expect it to appear twice or just verify it appears.
	require.Equal(t, 2, strings.Count(string(content), `<span class="json-empty">empty</span>`),
		"Output should contain styled empty string in both Args and Results")
}

func TestNullJSON(t *testing.T) {
	m := map[string]any{"foo": "bar", "count": 42}
	val := spanner.NullJSON{Value: m, Valid: true}
	// nullJSON is unexported, ensuring we can test it in the same package
	got := nullJSON(val)

	// We expect valid JSON string.
	// Check for presence of key/value pairs in JSON format
	require.Contains(t, got, `"foo":"bar"`)
	require.Contains(t, got, `"count":42`)
	if strings.Contains(got, "map[") {
		t.Errorf("nullJSON returned map string representation: %q", got)
	}
}
