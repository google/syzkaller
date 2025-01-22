// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	baseURL string
}

func NewClient(url string) *Client {
	return &Client{baseURL: strings.TrimRight(url, "/")}
}

func (client Client) GetSessionSeries(_ context.Context, sessionID string) (*Series, error) {
	// TODO: add support for the context.
	return getJSON[Series](client.baseURL + "/sessions/" + sessionID + "/series")
}

func (client Client) GetSeries(_ context.Context, seriesID string) (*Series, error) {
	// TODO: add support for the context.
	return getJSON[Series](client.baseURL + "/series/" + seriesID)
}

func (client Client) SkipSession(ctx context.Context, sessionID string, req *SkipRequest) error {
	_, err := postJSON[SkipRequest, any](ctx, client.baseURL+"/sessions/"+sessionID+"/skip", req)
	return err
}

func (client Client) GetTrees() []*Tree {
	return defaultTrees
}

type LastBuildReq struct {
	Arch       string
	ConfigName string
	TreeName   string
}

func (client Client) LastSuccessfulBuild(ctx context.Context, req *LastBuildReq) (*Build, error) {
	return postJSON[LastBuildReq, Build](ctx, client.baseURL+"/builds/last", req)
}

type UploadBuildReq struct {
	Build
	Config []byte `json:"config"`
	Log    []byte `json:"log"`
}

type UploadBuildResp struct {
	ID string
}

func (client Client) UploadBuild(ctx context.Context, req *UploadBuildReq) (*UploadBuildResp, error) {
	return postJSON[UploadBuildReq, UploadBuildResp](ctx, client.baseURL+"/builds/upload", req)
}

func (client Client) UploadTestResult(ctx context.Context, req *TestResult) error {
	_, err := postJSON[TestResult, any](ctx, client.baseURL+"/tests/upload", req)
	return err
}

func (client Client) UploadFinding(ctx context.Context, req *Finding) error {
	_, err := postJSON[Finding, any](ctx, client.baseURL+"/findings/upload", req)
	return err
}

func getJSON[Resp any](url string) (*Resp, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := ensure200(resp); err != nil {
		return nil, err
	}
	var data Resp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func postJSON[Req any, Resp any](ctx context.Context, url string, req *Req) (*Resp, error) {
	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := ensure200(resp); err != nil {
		return nil, err
	}
	var data Resp
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func ensure200(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if len(bodyBytes) > 128 {
			bodyBytes = bodyBytes[:128]
		}
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, bodyBytes)
	}
	return nil
}
