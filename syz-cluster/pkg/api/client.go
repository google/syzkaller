// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
}

func NewClient(url string) *Client {
	return &Client{baseURL: strings.TrimRight(url, "/")}
}

func (client Client) GetSessionSeries(ctx context.Context, sessionID string) (*Series, error) {
	return getJSON[Series](ctx, client.baseURL+"/sessions/"+sessionID+"/series")
}

func (client Client) GetSeries(ctx context.Context, seriesID string) (*Series, error) {
	return getJSON[Series](ctx, client.baseURL+"/series/"+seriesID)
}

func (client Client) SkipSession(ctx context.Context, sessionID string, req *SkipRequest) error {
	_, err := postJSON[SkipRequest, any](ctx, client.baseURL+"/sessions/"+sessionID+"/skip", req)
	return err
}

type TreesResp struct {
	Trees []*Tree `json:"trees"`
}

func (client Client) GetTrees(ctx context.Context) (*TreesResp, error) {
	return getJSON[TreesResp](ctx, client.baseURL+"/trees")
}

type LastBuildReq struct {
	Arch       string
	ConfigName string
	TreeName   string
	Commit     string
	Status     string
}

const BuildSuccess = "success"

func (client Client) LastBuild(ctx context.Context, req *LastBuildReq) (*Build, error) {
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

func (client Client) UploadFinding(ctx context.Context, req *NewFinding) error {
	_, err := postJSON[NewFinding, any](ctx, client.baseURL+"/findings/upload", req)
	return err
}

type UploadSeriesResp struct {
	ID    string `json:"id"`
	Saved bool   `json:"saved"`
}

func (client Client) UploadSeries(ctx context.Context, req *Series) (*UploadSeriesResp, error) {
	return postJSON[Series, UploadSeriesResp](ctx, client.baseURL+"/series/upload", req)
}

type UploadSessionResp struct {
	ID string `json:"id"`
}

func (client Client) UploadSession(ctx context.Context, req *NewSession) (*UploadSessionResp, error) {
	return postJSON[NewSession, UploadSessionResp](ctx, client.baseURL+"/sessions/upload", req)
}

const requestTimeout = time.Minute

func finishRequest[Resp any](httpReq *http.Request) (*Resp, error) {
	client := &http.Client{
		Timeout: requestTimeout,
	}
	resp, err := client.Do(httpReq)
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
