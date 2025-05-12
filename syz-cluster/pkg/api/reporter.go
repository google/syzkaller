// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"context"
	"net/url"
	"strings"
	"time"
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

const LKMLReporter = "lkml"

func (client ReporterClient) GetNextReport(ctx context.Context, reporter string) (*NextReportResp, error) {
	v := url.Values{}
	v.Add("reporter", reporter)
	return postJSON[any, NextReportResp](ctx, client.baseURL+"/reports?"+v.Encode(), nil)
}

type UpdateReportReq struct {
	MessageID string `json:"message_id"`
}

// UpdateReport may be used to remember the message ID and the link to the discussion.
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

type RecordReplyReq struct {
	MessageID string    `json:"message_id"`
	InReplyTo string    `json:"in_reply_to"`
	Reporter  string    `json:"reporter"`
	Time      time.Time `json:"time"`
}

type RecordReplyResp struct {
	New      bool   `json:"new"`
	ReportID string `json:"report_id"` // or empty, if no original message was found
}

func (client ReporterClient) RecordReply(ctx context.Context, req *RecordReplyReq) (*RecordReplyResp, error) {
	return postJSON[RecordReplyReq, RecordReplyResp](ctx, client.baseURL+"/reports/record_reply", req)
}

type LastReplyResp struct {
	Time time.Time `json:"time"`
}

// Returns nil if no reply has ever been recorded.
func (client ReporterClient) LastReply(ctx context.Context, reporter string) (*LastReplyResp, error) {
	v := url.Values{}
	v.Add("reporter", reporter)
	return postJSON[any, LastReplyResp](ctx, client.baseURL+"/reports/last_reply?"+v.Encode(), nil)
}
