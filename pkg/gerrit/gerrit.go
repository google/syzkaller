// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gerrit provides gerrit client for:
// https://linux.googlesource.com/Documentation/#gerrit-code-reviews-for-the-linux-kernel
// For documentation on the API see:
// https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html
package gerrit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const host = "https://linux-review.googlesource.com"

func CreateChange(ctx context.Context, repo, branch, baseCommit, description, diff string) (
	changeID int, link string, err error) {
	project, err := projectForRepo(repo)
	if err != nil {
		return 0, "", err
	}
	req := map[string]any{
		"project":     project,
		"branch":      branch,
		"subject":     description,
		"base_commit": baseCommit,
		"patch": map[string]any{
			"patch": diff,
		},
	}
	resp := new(struct {
		Number int `json:"_number"`
	})
	err = request(ctx, "changes/", req, resp)
	link = fmt.Sprintf("%v/c/%v/+/%v", host, project, resp.Number)
	return resp.Number, link, err
}

func request(ctx context.Context, api string, req map[string]any, resp any) error {
	ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/gerritcodereview")
	if err != nil {
		return fmt.Errorf("gerrit: failed to get token source: %w", err)
	}
	reqData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("gerrit: failed to marshal CreateChange: %w", err)
	}
	endpoint := fmt.Sprintf("%v/a/%v", host, api)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqData))
	if err != nil {
		return fmt.Errorf("gerrit: failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=UTF-8")
	httpResp, err := oauth2.NewClient(ctx, ts).Do(httpReq)
	if err != nil {
		return fmt.Errorf("gerrit: failed to call %v: %w", api, err)
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(httpResp.Body)
	if err != nil || httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		return fmt.Errorf("gerrit: failed to call %v: %v %v err:%w: %s",
			api, httpResp.StatusCode, http.StatusText(httpResp.StatusCode), err, body)
	}
	// Responses may start with ")]}'" for XSSI protection; trim it.
	const xssiPrefix = ")]}'\n"
	body = bytes.TrimPrefix(body, []byte(xssiPrefix))
	if err := json.Unmarshal(body, resp); err != nil {
		return fmt.Errorf("gerrit: failed to unmarshal %v response: %w\n%s", api, err, body)
	}
	return nil
}
