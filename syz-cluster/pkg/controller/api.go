// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// nolint: dupl // The methods look similar, but extracting the common parts will only make the code worse.
package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
)

type APIServer struct {
	seriesService  *service.SeriesService
	sessionService *service.SessionService
	buildService   *service.BuildService
	testService    *service.SessionTestService
	findingService *service.FindingService
}

func NewAPIServer(env *app.AppEnvironment) *APIServer {
	return &APIServer{
		seriesService:  service.NewSeriesService(env),
		sessionService: service.NewSessionService(env),
		buildService:   service.NewBuildService(env),
		testService:    service.NewSessionTestService(env),
		findingService: service.NewFindingService(env),
	}
}

func (c APIServer) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions/{session_id}/series", c.getSessionSeries)
	mux.HandleFunc("/sessions/{session_id}/skip", c.skipSession)
	mux.HandleFunc("/sessions/upload", c.uploadSession)
	mux.HandleFunc("/series/{series_id}", c.getSeries)
	mux.HandleFunc("/builds/last", c.getLastBuild)
	mux.HandleFunc("/builds/upload", c.uploadBuild)
	mux.HandleFunc("/tests/upload", c.uploadTest)
	mux.HandleFunc("/findings/upload", c.uploadFinding)
	mux.HandleFunc("/series/upload", c.uploadSeries)
	return mux
}

func (c APIServer) getSessionSeries(w http.ResponseWriter, r *http.Request) {
	resp, err := c.seriesService.GetSessionSeries(r.Context(), r.PathValue("session_id"))
	if err == service.ErrSeriesNotFound || err == service.ErrSessionNotFound {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c APIServer) skipSession(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.SkipRequest](w, r)
	if req == nil {
		return
	}
	err := c.sessionService.SkipSession(r.Context(), r.PathValue("session_id"), req)
	if errors.Is(err, service.ErrSessionNotFound) {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c APIServer) getSeries(w http.ResponseWriter, r *http.Request) {
	resp, err := c.seriesService.GetSeries(r.Context(), r.PathValue("series_id"))
	if errors.Is(err, service.ErrSeriesNotFound) {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c APIServer) uploadBuild(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.UploadBuildReq](w, r)
	if req == nil {
		return
	}
	resp, err := c.buildService.Upload(r.Context(), req)
	if err != nil {
		// TODO: sometimes it's not StatusInternalServerError.
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply(w, resp)
}

func (c APIServer) uploadTest(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.TestResult](w, r)
	if req == nil {
		return
	}
	// TODO: add parameters validation (and also of the Log size).
	err := c.testService.Save(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c APIServer) uploadFinding(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.Finding](w, r)
	if req == nil {
		return
	}
	// TODO: add parameters validation.
	err := c.findingService.Save(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[interface{}](w, nil)
}

func (c APIServer) getLastBuild(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.LastBuildReq](w, r)
	if req == nil {
		return
	}
	resp, err := c.buildService.LastBuild(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[*api.Build](w, resp)
}

func (c APIServer) uploadSeries(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.Series](w, r)
	if req == nil {
		return
	}
	resp, err := c.seriesService.UploadSeries(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[*api.UploadSeriesResp](w, resp)
}

func (c APIServer) uploadSession(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.NewSession](w, r)
	if req == nil {
		return
	}
	resp, err := c.sessionService.UploadSession(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	reply[*api.UploadSessionResp](w, resp)
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
