// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type dashboardHandler struct {
	seriesRepo      *db.SeriesRepository
	sessionRepo     *db.SessionRepository
	sessionTestRepo *db.SessionTestRepository
	findingRepo     *db.FindingRepository
	blobStorage     blob.Storage
	templates       map[string]*template.Template
}

//go:embed templates/*
var templates embed.FS

func newHandler(env *app.AppEnvironment) (*dashboardHandler, error) {
	perFile := map[string]*template.Template{}
	var err error
	for _, name := range []string{"index.html", "series.html"} {
		perFile[name], err = template.ParseFS(templates, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, err
		}
	}
	return &dashboardHandler{
		templates:       perFile,
		blobStorage:     env.BlobStorage,
		seriesRepo:      db.NewSeriesRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		sessionTestRepo: db.NewSessionTestRepository(env.Spanner),
		findingRepo:     db.NewFindingRepository(env.Spanner),
	}, nil
}

//go:embed static
var staticFs embed.FS

func (h *dashboardHandler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions/{id}/log", errToStatus(h.sessionLog))
	mux.HandleFunc("/sessions/{id}/test_logs", errToStatus(h.sessionTestLog))
	mux.HandleFunc("/series/{id}", errToStatus(h.seriesInfo))
	mux.HandleFunc("/patches/{id}", errToStatus(h.patchContent))
	mux.HandleFunc("/findings/{id}/{key}", errToStatus(h.findingInfo))
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

// TODO: export a common method to get Series' status.

func (h *dashboardHandler) seriesList(w http.ResponseWriter, r *http.Request) error {
	type MainPageData struct {
		// It's probably not the best idea to expose db entities here,
		// but so far redefining the entity would just duplicate the code.
		List []*db.SeriesWithSession
	}
	var data MainPageData
	var err error
	data.List, err = h.seriesRepo.ListLatest(r.Context(), time.Time{}, 0)
	if err != nil {
		return fmt.Errorf("failed to query the list: %w", err)
	}
	return h.templates["index.html"].ExecuteTemplate(w, "base.html", data)
}

func (h *dashboardHandler) seriesInfo(w http.ResponseWriter, r *http.Request) error {
	type SessionTest struct {
		*db.FullSessionTest
		Findings []*db.Finding
	}
	type SessionData struct {
		*db.Session
		Tests []SessionTest
	}
	type SeriesData struct {
		*db.Series
		Patches      []*db.Patch
		Sessions     []SessionData
		TotalPatches int
	}
	var data SeriesData
	var err error
	ctx := r.Context()
	data.Series, err = h.seriesRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		return fmt.Errorf("failed to query series: %w", err)
	} else if data.Series == nil {
		return fmt.Errorf("%w: series", errNotFound)
	}
	data.Patches, err = h.seriesRepo.ListPatches(ctx, data.Series)
	if err != nil {
		return fmt.Errorf("failed to query patches: %w", err)
	}
	data.TotalPatches = len(data.Patches)
	sessions, err := h.sessionRepo.ListForSeries(ctx, data.Series)
	if err != nil {
		return fmt.Errorf("failed to query sessions: %w", err)
	}
	for _, session := range sessions {
		rawTests, err := h.sessionTestRepo.BySession(ctx, session.ID)
		if err != nil {
			return fmt.Errorf("failed to query session tests: %w", err)
		}
		findings, err := h.findingRepo.ListForSession(ctx, session.ID)
		if err != nil {
			return fmt.Errorf("failed to query session findings: %w", err)
		}
		perName := groupFindings(findings)
		sessionData := SessionData{
			Session: session,
		}
		for _, test := range rawTests {
			sessionData.Tests = append(sessionData.Tests, SessionTest{
				FullSessionTest: test,
				Findings:        perName[test.TestName],
			})
		}
		data.Sessions = append(data.Sessions, sessionData)
	}
	return h.templates["series.html"].ExecuteTemplate(w, "base.html", data)
}

func groupFindings(findings []*db.Finding) map[string][]*db.Finding {
	ret := map[string][]*db.Finding{}
	for _, finding := range findings {
		ret[finding.TestName] = append(ret[finding.TestName], finding)
	}
	return ret
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
func (h *dashboardHandler) patchContent(w http.ResponseWriter, r *http.Request) error {
	patch, err := h.seriesRepo.PatchByID(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	} else if patch == nil {
		return fmt.Errorf("%w: patch", errNotFound)
	}
	return h.streamBlob(w, patch.BodyURI)
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
	default:
		return fmt.Errorf("%w: unknown key value", errBadRequest)
	}
}

func (h *dashboardHandler) sessionTestLog(w http.ResponseWriter, r *http.Request) error {
	test, err := h.sessionTestRepo.Get(r.Context(), r.PathValue("id"), r.FormValue("name"))
	if err != nil {
		return err
	} else if test == nil {
		return fmt.Errorf("%w: test log", errNotFound)
	}
	return h.streamBlob(w, test.LogURI)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
