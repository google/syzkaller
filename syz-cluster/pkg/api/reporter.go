// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"context"
	"strings"
)

type ReporterClient struct {
	baseURL string
}

func NewReporterClient(url string) *ReporterClient {
	return &ReporterClient{baseURL: strings.TrimRight(url, "/")}
}

type NextReportResp struct {
	Report *SessionReport `json:"report"`
}

func (client ReporterClient) GetNextReport(ctx context.Context) (*NextReportResp, error) {
	return postJSON[any, NextReportResp](ctx, client.baseURL+"/reports", nil)
}

// TODO: What to do if sending the report failed? Retry or mark as failed?

type UpdateReportReq struct {
	Link string `json:"link"`
}

func (client ReporterClient) UpdateReport(ctx context.Context, id string, req *UpdateReportReq) error {
	_, err := postJSON[UpdateReportReq, any](ctx, client.baseURL+"/reports/"+id+"/update", req)
	return err
}

// ConfirmReport should be called to mark a report as sent.
func (client ReporterClient) ConfirmReport(ctx context.Context, id string) error {
	_, err := postJSON[any, any](ctx, client.baseURL+"/reports/"+id+"/confirm", nil)
	return err
}

type UpstreamReportReq struct {
	User string `json:"user"`
}

func (client ReporterClient) UpstreamReport(ctx context.Context, id string, req *UpstreamReportReq) error {
	_, err := postJSON[UpstreamReportReq, any](ctx, client.baseURL+"/reports/"+id+"/upstream", req)
	return err
}
