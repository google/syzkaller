// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reporter

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/service"
)

type APIServer struct {
	service *service.ReportService
}

func NewAPIServer(service *service.ReportService) *APIServer {
	return &APIServer{service: service}
}

func (s *APIServer) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/reports/{report_id}/update", s.updateReport)
	mux.HandleFunc("/reports/{report_id}/upstream", s.upstreamReport)
	mux.HandleFunc("/reports/{report_id}/confirm", s.confirmReport)
	mux.HandleFunc("/reports", s.nextReports)
	return mux
}

// nolint: dupl
func (s *APIServer) updateReport(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.UpdateReportReq](w, r)
	if req == nil {
		return // TODO: return StatusBadRequest here and below.
	}
	err := s.service.Update(r.Context(), r.PathValue("report_id"), req)
	reply[interface{}](w, nil, err)
}

// nolint: dupl
func (s *APIServer) upstreamReport(w http.ResponseWriter, r *http.Request) {
	req := api.ParseJSON[api.UpstreamReportReq](w, r)
	if req == nil {
		return
	}
	// TODO: journal the action.
	err := s.service.Upstream(r.Context(), r.PathValue("report_id"), req)
	reply[interface{}](w, nil, err)
}

func (s *APIServer) nextReports(w http.ResponseWriter, r *http.Request) {
	resp, err := s.service.Next(r.Context(), r.FormValue("reporter"))
	reply(w, resp, err)
}

func (s *APIServer) confirmReport(w http.ResponseWriter, r *http.Request) {
	err := s.service.Confirm(r.Context(), r.PathValue("report_id"))
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
