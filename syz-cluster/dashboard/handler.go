// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/html/urlutil"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
)

type dashboardHandler struct {
	title               string
	buildRepo           *db.BuildRepository
	seriesRepo          *db.SeriesRepository
	sessionRepo         *db.SessionRepository
	sessionTestRepo     *db.SessionTestRepository
	sessionTestStepRepo *db.SessionTestStepRepository
	findingRepo         *db.FindingRepository
	statsRepo           *db.StatsRepository
	jobRepo             *db.JobRepository
	blobStorage         blob.Storage
	templates           map[string]*template.Template
}

//go:embed templates/*
var templates embed.FS

func newHandler(env *app.AppEnvironment) (*dashboardHandler, error) {
	perFile := map[string]*template.Template{}
	var err error
	for _, name := range []string{"index.html", "series.html", "graphs.html"} {
		perFile[name], err = template.ParseFS(templates,
			"templates/base.html", "templates/templates.html", "templates/"+name)
		if err != nil {
			return nil, err
		}
	}
	return &dashboardHandler{
		title:               env.Config.Name,
		templates:           perFile,
		blobStorage:         env.BlobStorage,
		buildRepo:           db.NewBuildRepository(env.Spanner),
		seriesRepo:          db.NewSeriesRepository(env.Spanner),
		sessionRepo:         db.NewSessionRepository(env.Spanner),
		sessionTestRepo:     db.NewSessionTestRepository(env.Spanner),
		sessionTestStepRepo: db.NewSessionTestStepRepository(env.Spanner),
		findingRepo:         db.NewFindingRepository(env.Spanner),
		statsRepo:           db.NewStatsRepository(env.Spanner),
		jobRepo:             db.NewJobRepository(env.Spanner),
	}, nil
}

//go:embed static
var staticFs embed.FS

func (h *dashboardHandler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions/{id}/log", errToStatus(h.sessionLog))
	mux.HandleFunc("/sessions/{id}/triage_log", errToStatus(h.sessionTriageLog))
	mux.HandleFunc("/sessions/{id}/test_logs", errToStatus(h.sessionTestLog))
	mux.HandleFunc("/test_steps/{step_id}/log", errToStatus(h.sessionTestStepLog))
	mux.HandleFunc("/sessions/{id}/test_artifacts", errToStatus(h.sessionTestArtifacts))
	mux.HandleFunc("/series/{id}/all_patches", errToStatus(h.allPatches))
	mux.HandleFunc("/series/{id}", errToStatus(h.seriesInfo))
	mux.HandleFunc("/session/{id}", errToStatus(h.sessionInfo))
	mux.HandleFunc("/patches/{id}", errToStatus(h.patchContent))
	mux.HandleFunc("/jobs/{id}/patch", errToStatus(h.jobPatchContent))
	mux.HandleFunc("/findings/{id}/{key}", errToStatus(h.findingInfo))
	mux.HandleFunc("/builds/{id}/{key}", errToStatus(h.buildInfo))
	mux.HandleFunc("/stats", errToStatus(h.statsPage))
	mux.HandleFunc("/", errToStatus(h.seriesList))
	staticFiles, err := fs.Sub(staticFs, "static")
	if err != nil {
		app.Fatalf("failed to parse templates: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))
	return mux
}

var (
	errNotFound   = errors.New("not found error")
	errBadRequest = errors.New("bad request")
)

type statusOption struct {
	Key   db.SessionStatus
	Value string
}

func (h *dashboardHandler) seriesList(w http.ResponseWriter, r *http.Request) error {
	type MainPageData struct {
		// It's probably not the best idea to expose db entities here,
		// but so far redefining the entity would just duplicate the code.
		List     []*db.SeriesWithSession
		Filter   db.SeriesFilter
		Statuses []statusOption
		// This is very primitive, but better than nothing.
		FilterFormURL string
		PrevPageURL   string
		NextPageURL   string
	}
	const perPage = 100
	offset, err := h.getOffset(r)
	if err != nil {
		return err
	}
	baseURL := r.URL.RequestURI()
	data := MainPageData{
		Filter: db.SeriesFilter{
			Cc:            r.FormValue("cc"),
			Status:        db.SessionStatus(r.FormValue("status")),
			WithFindings:  r.FormValue("with_findings") != "",
			PreventedBugs: r.FormValue("prevented_bugs") != "",
			Limit:         perPage,
			Offset:        offset,
			Name:          r.FormValue("name"),
		},
		// If the filters are changed, the old offset value is irrelevant.
		FilterFormURL: urlutil.DropParam(baseURL, "offset", ""),
		Statuses: []statusOption{
			{db.SessionStatusAny, "any"},
			{db.SessionStatusWaiting, "waiting"},
			{db.SessionStatusInProgress, "in progress"},
			{db.SessionStatusFinished, "finished"},
			{db.SessionStatusSkipped, "skipped"},
			{db.SessionStatusStepsFailed, "steps failed"},
		},
	}

	data.List, err = h.seriesRepo.ListLatest(r.Context(), data.Filter, time.Time{})
	if err != nil {
		return fmt.Errorf("failed to query the list: %w", err)
	}
	if data.Filter.Offset > 0 {
		data.PrevPageURL = urlutil.SetParam(baseURL, "offset",
			fmt.Sprintf("%d", max(0, data.Filter.Offset-perPage)))
	}
	// TODO: this is not strictly correct (we also need to check whether there actually more rows).
	// But let's tolerate it for now.
	if len(data.List) == data.Filter.Limit {
		data.NextPageURL = urlutil.SetParam(baseURL, "offset",
			fmt.Sprintf("%d", data.Filter.Offset+len(data.List)))
	}
	return h.renderTemplate(w, "index.html", data)
}

func (h *dashboardHandler) getOffset(r *http.Request) (int, error) {
	val := r.FormValue("offset")
	if val == "" {
		return 0, nil
	}
	i, err := strconv.Atoi(val)
	if err != nil || i < 0 {
		return 0, fmt.Errorf("%w: invalid offset value", errBadRequest)
	}
	return i, nil
}

type uiSessionTest struct {
	*db.FullSessionTest
	Findings []*db.Finding
	Steps    []*db.TestStepGroup
}

type uiSessionData struct {
	*db.Session
	Tests       []uiSessionTest
	Uncollapsed bool
	Job         *db.Job
	JobLink     string
}

type uiSeriesData struct {
	*db.Series
	Patches      []*db.Patch
	Sessions     []uiSessionData
	Versions     []*db.Series
	TotalPatches int
}

func (h *dashboardHandler) fetchSessionData(ctx context.Context, session *db.Session) (uiSessionData, error) {
	rawTests, err := h.sessionTestRepo.BySession(ctx, session.ID)
	if err != nil {
		return uiSessionData{}, fmt.Errorf("failed to query session tests: %w", err)
	}
	findings, err := h.findingRepo.ListForSession(ctx, session.ID, db.NoLimit)
	if err != nil {
		return uiSessionData{}, fmt.Errorf("failed to query session findings: %w", err)
	}
	perName := groupFindings(findings)
	sessionData := uiSessionData{
		Session: session,
	}
	if !session.JobID.IsNull() {
		dbJob, err := h.jobRepo.GetByID(ctx, session.JobID.StringVal)
		if err != nil {
			return uiSessionData{}, fmt.Errorf("failed to query job: %w", err)
		}
		if dbJob != nil {
			sessionData.JobLink = service.JobLink(dbJob)
		}
		sessionData.Job = dbJob
	}
	for _, test := range rawTests {
		steps, err := h.sessionTestStepRepo.ListForSession(ctx, session.ID, test.TestName)
		if err != nil {
			return uiSessionData{}, fmt.Errorf("failed to query session test steps: %w", err)
		}
		groupedSteps := db.GroupTestSteps(steps)
		sessionData.Tests = append(sessionData.Tests, uiSessionTest{
			FullSessionTest: test,
			Findings:        perName[test.TestName],
			Steps:           groupedSteps,
		})
	}
	return sessionData, nil
}

func (h *dashboardHandler) populateSeriesMetadata(ctx context.Context, data *uiSeriesData) error {
	var err error
	data.Patches, err = h.seriesRepo.ListPatches(ctx, data.Series)
	if err != nil {
		return fmt.Errorf("failed to query patches: %w", err)
	}
	data.TotalPatches = len(data.Patches)
	data.Versions, err = h.seriesRepo.ListAllVersions(ctx, data.Series.Title)
	if err != nil {
		return fmt.Errorf("failed to query all series versions: %w", err)
	}
	return nil
}

func (h *dashboardHandler) seriesInfo(w http.ResponseWriter, r *http.Request) error {
	var data uiSeriesData
	var err error
	ctx := r.Context()
	data.Series, err = h.seriesRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		return fmt.Errorf("failed to query series: %w", err)
	} else if data.Series == nil {
		return fmt.Errorf("%w: series", errNotFound)
	}
	if err := h.populateSeriesMetadata(ctx, &data); err != nil {
		return err
	}
	sessions, err := h.sessionRepo.ListForSeries(ctx, data.Series)
	if err != nil {
		return fmt.Errorf("failed to query sessions: %w", err)
	}
	for _, session := range sessions {
		sessionData, err := h.fetchSessionData(ctx, session)
		if err != nil {
			return err
		}
		sessionData.Uncollapsed = session.JobID.IsNull()
		data.Sessions = append(data.Sessions, sessionData)
	}
	sort.Slice(data.Sessions, func(i, j int) bool {
		if data.Sessions[i].JobID.IsNull() && !data.Sessions[j].JobID.IsNull() {
			return true
		}
		if !data.Sessions[i].JobID.IsNull() && data.Sessions[j].JobID.IsNull() {
			return false
		}
		return data.Sessions[i].CreatedAt.After(data.Sessions[j].CreatedAt)
	})
	return h.renderTemplate(w, "series.html", data)
}

func (h *dashboardHandler) sessionInfo(w http.ResponseWriter, r *http.Request) error {
	var data uiSeriesData
	var err error
	ctx := r.Context()

	session, err := h.sessionRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		return fmt.Errorf("failed to query session: %w", err)
	} else if session == nil {
		return fmt.Errorf("%w: session", errNotFound)
	}

	data.Series, err = h.seriesRepo.GetByID(ctx, session.SeriesID)
	if err != nil {
		return fmt.Errorf("failed to query series: %w", err)
	} else if data.Series == nil {
		return fmt.Errorf("%w: series", errNotFound)
	}
	if err := h.populateSeriesMetadata(ctx, &data); err != nil {
		return err
	}

	sessionData, err := h.fetchSessionData(ctx, session)
	if err != nil {
		return err
	}
	sessionData.Uncollapsed = true
	data.Sessions = []uiSessionData{sessionData}

	return h.renderTemplate(w, "series.html", data)
}

func (h *dashboardHandler) statsPage(w http.ResponseWriter, r *http.Request) error {
	type StatsPageData struct {
		Processed     []*db.CountPerWeek
		Findings      []*db.CountPerWeek
		Reports       []*db.CountPerWeek
		Delay         []*db.DelayPerWeek
		Distribution  []*db.StatusPerWeek
		PreventedBugs []*db.PreventedBugsStats
		MonthlyStats  MonthlyStats
	}
	var data StatsPageData
	var err error
	data.Processed, err = h.statsRepo.ProcessedSeriesPerWeek(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query processed series data: %w", err)
	}
	data.Findings, err = h.statsRepo.FindingsPerWeek(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query findings data: %w", err)
	}
	data.Reports, err = h.statsRepo.ReportsPerWeek(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query reports data: %w", err)
	}
	data.Delay, err = h.statsRepo.DelayPerWeek(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query delay data: %w", err)
	}
	data.Distribution, err = h.statsRepo.SessionStatusPerWeek(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query distribution data: %w", err)
	}
	data.PreventedBugs, err = h.statsRepo.PreventedBugsPerMonth(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query prevented bugs data: %w", err)
	}

	reportsPerMonth, err := h.statsRepo.ReportsPerMonth(r.Context())
	if err != nil {
		return fmt.Errorf("failed to query reports per month: %w", err)
	}
	data.MonthlyStats = makeMonthlyStats(reportsPerMonth)

	return h.renderTemplate(w, "graphs.html", data)
}

type MonthlyStats struct {
	Totals *db.ReportsPerMonth
	Months []*db.ReportsPerMonth
}

func makeMonthlyStats(reports []*db.ReportsPerMonth) MonthlyStats {
	totals := &db.ReportsPerMonth{}
	for _, r := range reports {
		totals.Reports += r.Reports
		totals.Findings += r.Findings
	}

	return MonthlyStats{
		Totals: totals,
		Months: reports,
	}
}

func groupFindings(findings []*db.Finding) map[string][]*db.Finding {
	ret := map[string][]*db.Finding{}
	for _, finding := range findings {
		ret[finding.TestName] = append(ret[finding.TestName], finding)
	}
	return ret
}

func (h *dashboardHandler) renderTemplate(w http.ResponseWriter, name string, data any) error {
	type page struct {
		Title    string
		Template string
		Data     any
	}
	return h.templates[name].ExecuteTemplate(w, "base.html", page{
		Title:    h.title,
		Template: name,
		Data:     data,
	})
}

// nolint:dupl
func (h *dashboardHandler) sessionLog(w http.ResponseWriter, r *http.Request) error {
	session, err := h.sessionRepo.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if session == nil {
		return fmt.Errorf("%w: session", errNotFound)
	}
	return h.streamBlob(w, session.LogURI)
}

// nolint:dupl
func (h *dashboardHandler) sessionTriageLog(w http.ResponseWriter, r *http.Request) error {
	session, err := h.sessionRepo.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if session == nil {
		return fmt.Errorf("%w: session", errNotFound)
	}
	return h.streamBlob(w, session.TriageLogURI)
}

// nolint:dupl
func (h *dashboardHandler) patchContent(w http.ResponseWriter, r *http.Request) error {
	patch, err := h.seriesRepo.PatchByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if patch == nil {
		return fmt.Errorf("%w: patch", errNotFound)
	}
	return h.streamBlob(w, patch.BodyURI)
}

// nolint:dupl
func (h *dashboardHandler) jobPatchContent(w http.ResponseWriter, r *http.Request) error {
	job, err := h.jobRepo.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if job == nil {
		return fmt.Errorf("%w: job", errNotFound)
	}
	return h.streamBlob(w, job.PatchURI)
}

func (h *dashboardHandler) allPatches(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	series, err := h.seriesRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		return fmt.Errorf("failed to query series: %w", err)
	} else if series == nil {
		return fmt.Errorf("%w: series", errNotFound)
	}
	patches, err := h.seriesRepo.ListPatches(ctx, series)
	if err != nil {
		return fmt.Errorf("failed to query patches: %w", err)
	}
	for _, patch := range patches {
		err = h.streamBlob(w, patch.BodyURI)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *dashboardHandler) findingInfo(w http.ResponseWriter, r *http.Request) error {
	finding, err := h.findingRepo.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if finding == nil {
		return fmt.Errorf("%w: finding", errNotFound)
	}
	switch r.PathValue("key") {
	case "report":
		return h.streamBlob(w, finding.ReportURI)
	case "log":
		return h.streamBlob(w, finding.LogURI)
	case "syz_repro":
		opts, err := blob.ReadAllBytes(h.blobStorage, finding.SyzReproOptsURI)
		if err != nil {
			return err
		}
		repro, err := blob.ReadAllBytes(h.blobStorage, finding.SyzReproURI)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "# %s\n", opts)
		_, err = w.Write(repro)
		return err
	case "c_repro":
		return h.streamBlob(w, finding.CReproURI)
	default:
		return fmt.Errorf("%w: unknown key value", errBadRequest)
	}
}

func (h *dashboardHandler) buildInfo(w http.ResponseWriter, r *http.Request) error {
	build, err := h.buildRepo.GetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if build == nil {
		return fmt.Errorf("%w: build", errNotFound)
	}
	switch r.PathValue("key") {
	case "log":
		return h.streamBlob(w, build.LogURI)
	case "config":
		return h.streamBlob(w, build.ConfigURI)
	default:
		return fmt.Errorf("%w: unknown key value", errBadRequest)
	}
}

func (h *dashboardHandler) sessionTestLog(w http.ResponseWriter, r *http.Request) error {
	test, err := h.sessionTestRepo.Get(r.Context(), r.PathValue("id"), r.FormValue("name"))
	if err != nil {
		return err
	} else if test == nil {
		return fmt.Errorf("%w: test", errNotFound)
	}
	return h.streamBlob(w, test.LogURI)
}

func (h *dashboardHandler) sessionTestArtifacts(w http.ResponseWriter, r *http.Request) error {
	test, err := h.sessionTestRepo.Get(r.Context(), r.PathValue("id"), r.FormValue("name"))
	if err != nil {
		return err
	} else if test == nil {
		return fmt.Errorf("%w: test", errNotFound)
	}
	filename := fmt.Sprintf("%s_%s.tar.gz", test.SessionID, test.TestName)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	return h.streamBlob(w, test.ArtifactsArchiveURI)
}

func (h *dashboardHandler) sessionTestStepLog(w http.ResponseWriter, r *http.Request) error {
	stepID := r.PathValue("step_id")
	step, err := h.sessionTestStepRepo.GetByID(r.Context(), stepID)
	if err != nil {
		return err
	} else if step == nil {
		return fmt.Errorf("%w: step", errNotFound)
	}
	return h.streamBlob(w, step.LogURI)
}

func (h *dashboardHandler) streamBlob(w http.ResponseWriter, uri string) error {
	if uri == "" {
		return nil
	}
	reader, err := h.blobStorage.Read(uri)
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = io.Copy(w, reader)
	return err
}

func errToStatus(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if errors.Is(err, errNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
		} else if errors.Is(err, errBadRequest) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else if err != nil {
			// TODO: if the error happened in the template, likely we've already printed
			// something to w. Unless we're in streamBlob(), it makes sense to first collect
			// the output in some buffer and only dump it after the exit from the handler.
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
