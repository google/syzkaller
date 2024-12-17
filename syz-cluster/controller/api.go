// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type ControllerAPI struct {
	seriesService *SeriesService
	buildService  *BuildService
	testRepo      *db.SessionTestRepository
}

func NewControllerAPI(env *app.AppEnvironment) *ControllerAPI {
	return &ControllerAPI{
		seriesService: NewSeriesService(env),
		buildService:  NewBuildService(env),
		testRepo:      db.NewSessionTestRepository(env.Spanner),
	}
}

func (c ControllerAPI) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/series/{id}", c.getSeries)
	mux.HandleFunc("/builds/last", c.getLastBuild)
	mux.HandleFunc("/builds/upload", c.uploadBuild)
	mux.HandleFunc("/tests/upload", c.uploadTest)
	//	mux.HandleFunc("/sessions/{id}/set-kernel", c.setSessionKernel)
	return mux
}

func (c ControllerAPI) getSeries(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	resp, err := c.seriesService.GetSeries(ctx, r.PathValue("id"))
	if err == ErrSeriesNotFound {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if err != nil {
		// TODO: sometimes it's not StatusInternalServerError.
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
	err := c.testRepo.Insert(context.Background(), &db.SessionTest{
		SessionID:      req.SessionID,
		BaseBuildID:    req.BaseBuildID,
		PatchedBuildID: req.PatchedBuildID,
		TestName:       req.TestName,
		Result:         req.Result,
	})
	if err != nil {
		// TODO: sometimes it's not StatusInternalServerError.
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
