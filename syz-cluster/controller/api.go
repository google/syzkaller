// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// nolint: dupl // The methods look similar, but extracting the common parts will only make the code worse.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

type ControllerAPI struct {
	seriesService  *SeriesService
	buildService   *BuildService
	testService    *SessionTestService
	findingService *FindingService
}

func NewControllerAPI(env *app.AppEnvironment) *ControllerAPI {
	return &ControllerAPI{
		seriesService:  NewSeriesService(env),
		buildService:   NewBuildService(env),
		testService:    NewSessionTestService(env),
		findingService: NewFindingService(env),
	}
}

func (c ControllerAPI) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions/{session_id}/series", c.getSessionSeries)
	mux.HandleFunc("/sessions/{session_id}/skip", c.skipSession)
	mux.HandleFunc("/series/{series_id}", c.getSeries)
	mux.HandleFunc("/builds/last", c.getLastBuild)
	mux.HandleFunc("/builds/upload", c.uploadBuild)
	mux.HandleFunc("/tests/upload", c.uploadTest)
	mux.HandleFunc("/findings/upload", c.uploadFinding)
	return mux
}

func (c ControllerAPI) getSessionSeries(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	resp, err := c.seriesService.GetSessionSeries(ctx, r.PathValue("session_id"))
	if err == ErrSeriesNotFound || err == ErrSessionNotFound {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c ControllerAPI) skipSession(w http.ResponseWriter, r *http.Request) {
	req := parseBody[api.SkipRequest](w, r)
	if req == nil {
		return
	}
	ctx := context.Background()
	err := c.seriesService.SkipSession(ctx, r.PathValue("session_id"), req)
	if errors.Is(err, ErrSessionNotFound) {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c ControllerAPI) getSeries(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	resp, err := c.seriesService.GetSeries(ctx, r.PathValue("series_id"))
	if err == ErrSeriesNotFound {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c ControllerAPI) uploadBuild(w http.ResponseWriter, r *http.Request) {
	req := parseBody[api.UploadBuildReq](w, r)
	if req == nil {
		return
	}
	resp, err := c.buildService.Upload(context.Background(), req)
	if err != nil {
		// TODO: sometimes it's not StatusInternalServerError.
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c ControllerAPI) uploadTest(w http.ResponseWriter, r *http.Request) {
	req := parseBody[api.TestResult](w, r)
	if req == nil {
		return
	}
	// TODO: add parameters validation.
	err := c.testService.Save(context.Background(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c ControllerAPI) uploadFinding(w http.ResponseWriter, r *http.Request) {
	req := parseBody[api.Finding](w, r)
	if req == nil {
		return
	}
	// TODO: add parameters validation.
	err := c.findingService.Save(context.Background(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c ControllerAPI) getLastBuild(w http.ResponseWriter, r *http.Request) {
	req := parseBody[api.LastBuildReq](w, r)
	if req == nil {
		return
	}
	resp, err := c.buildService.LastBuild(context.Background(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[*api.Build](w, resp)
}

func reply[T any](w http.ResponseWriter, resp T) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, "failed to serialize the response", http.StatusInternalServerError)
		return
	}
}

func parseBody[T any](w http.ResponseWriter, r *http.Request) *T {
	if r.Method != http.MethodPost {
		http.Error(w, "must be called via POST", http.StatusMethodNotAllowed)
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return nil
	}
	var data T
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return nil
	}
	return &data
}
