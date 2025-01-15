// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type DashboardHandler struct {
	seriesRepo      *db.SeriesRepository
	sessionRepo     *db.SessionRepository
	sessionTestRepo *db.SessionTestRepository
	findingRepo     *db.FindingRepository
	blobStorage     blob.Storage
	templates       map[string]*template.Template
}

//go:embed templates/*
var templates embed.FS

func NewHandler(env *app.AppEnvironment) (*DashboardHandler, error) {
	perFile := map[string]*template.Template{}
	var err error
	for _, name := range []string{"index.html", "series.html"} {
		perFile[name], err = template.ParseFS(templates, "templates/base.html", "templates/"+name)
		if err != nil {
			return nil, err
		}
	}
	return &DashboardHandler{
		templates:       perFile,
		blobStorage:     env.BlobStorage,
		seriesRepo:      db.NewSeriesRepository(env.Spanner),
		sessionRepo:     db.NewSessionRepository(env.Spanner),
		sessionTestRepo: db.NewSessionTestRepository(env.Spanner),
		findingRepo:     db.NewFindingRepository(env.Spanner),
	}, nil
}

func (h *DashboardHandler) seriesList(w http.ResponseWriter, r *http.Request) {
	type MainPageData struct {
		// It's probably not the best idea to expose db entities here,
		// but so far redefining the entity would just duplicate the code.
		List []*db.SeriesWithSession
	}
	var data MainPageData
	var err error
	data.List, err = h.seriesRepo.ListLatest(context.Background(), time.Time{}, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to query the list: %v", err), http.StatusInternalServerError)
		return
	}
	err = h.templates["index.html"].ExecuteTemplate(w, "base.html", data)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}

func (h *DashboardHandler) seriesInfo(w http.ResponseWriter, r *http.Request) {
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
	ctx := context.Background()
	data.Series, err = h.seriesRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	data.Patches, err = h.seriesRepo.ListPatches(ctx, data.Series)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	data.TotalPatches = len(data.Patches)
	sessions, err := h.sessionRepo.ListForSeries(ctx, data.Series)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	for _, session := range sessions {
		rawTests, err := h.sessionTestRepo.BySession(ctx, session.ID)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
		}
		findings, err := h.findingRepo.ListForSession(ctx, session)
		if err != nil {
			http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
			return
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

	err = h.templates["series.html"].ExecuteTemplate(w, "base.html", data)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
	}
}

func groupFindings(findings []*db.Finding) map[string][]*db.Finding {
	ret := map[string][]*db.Finding{}
	for _, finding := range findings {
		ret[finding.TestName] = append(ret[finding.TestName], finding)
	}
	return ret
}

// nolint:dupl
func (h *DashboardHandler) sessionLog(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	session, err := h.sessionRepo.GetByID(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if session == nil {
		http.Error(w, "no such session exists in the DB", http.StatusNotFound)
		return
	}
	h.streamBlob(w, session.LogURI)
}

// nolint:dupl
func (h *DashboardHandler) patchContent(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	patch, err := h.seriesRepo.PatchByID(ctx, r.PathValue("id"))
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	if patch == nil {
		http.Error(w, "no such patch exists in the DB", http.StatusNotFound)
		return
	}
	h.streamBlob(w, patch.BodyURI)
}

func (h *DashboardHandler) streamBlob(w http.ResponseWriter, uri string) {
	if uri == "" {
		return
	}
	reader, err := h.blobStorage.Read(uri)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	defer reader.Close()
	_, err = io.Copy(w, reader)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
}
