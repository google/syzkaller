// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
)

type ReporterAPI struct {
	service *service.ReportService
}

func NewReporterAPI(service *service.ReportService) *ReporterAPI {
	return &ReporterAPI{service: service}
}

func (ra *ReporterAPI) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/reports/{report_id}/update", ra.updateReport)
	mux.HandleFunc("/reports/{report_id}/upstream", ra.upstreamReport)
	mux.HandleFunc("/reports/{report_id}/confirm", ra.confirmReport)
	mux.HandleFunc("/reports", ra.nextReports)
	return mux
}

// nolint: dupl
func (ra *ReporterAPI) updateReport(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.UpdateReportReq](w, r)
	if req == nil {
		return // TODO: return StatusBadRequest here and below.
	}
	err := ra.service.Update(r.Context(), r.PathValue("report_id"), req)
	reply[interface{}](w, nil, err)
}

// nolint: dupl
func (ra *ReporterAPI) upstreamReport(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.UpstreamReportReq](w, r)
	if req == nil {
		return
	}
	// TODO: journal the action.
	err := ra.service.Upstream(r.Context(), r.PathValue("report_id"), req)
	reply[interface{}](w, nil, err)
}

func (ra *ReporterAPI) nextReports(w http.ResponseWriter, r *http.Request) {
	resp, err := ra.service.Next(r.Context())
	reply(w, resp, err)
}

func (ra *ReporterAPI) confirmReport(w http.ResponseWriter, r *http.Request) {
	err := ra.service.Confirm(r.Context(), r.PathValue("report_id"))
	reply[interface{}](w, nil, err)
}

func reply[T any](w http.ResponseWriter, obj T, err error) {
	if errors.Is(err, service.ErrReportNotFound) {
		http.Error(w, fmt.Sprint(err), http.StatusNotFound)
		return
	} else if errors.Is(err, service.ErrNotOnModeration) {
		http.Error(w, fmt.Sprint(err), http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}
	api.ReplyJSON[T](w, obj)
}
