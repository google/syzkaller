// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package hubapi defines data structures and an HTTP client for syz-hub communication.
package hubapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/auth"
)

const (
	// PathConnect is the HTTP path for registering or re-registering a manager.
	PathConnect = "/api/connect"
	// PathSync is the HTTP path for exchanging programs and reproducers.
	PathSync = "/api/sync"
	// HeaderClient carries the hub client identity for pre-body authentication.
	HeaderClient = "X-Syz-Client"
	// HeaderManager carries the optional manager instance name (prefixed by client).
	HeaderManager = "X-Syz-Manager"
)

// Input represents a fuzzing program returned by syz-hub along with its source domain.
type Input struct {
	Domain string `json:"domain,omitempty"`
	Prog   []byte `json:"prog"`
}

// ConnectReq is sent to register or re-register a manager with syz-hub.
type ConnectReq struct {
	Manager string   `json:"-"`
	HTTP    string   `json:"http,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	Fresh   bool     `json:"fresh,omitempty"`
	Calls   []string `json:"calls,omitempty"`
	Corpus  [][]byte `json:"corpus,omitempty"`
}

// SyncReq is sent to exchange programs and reproducers with syz-hub.
type SyncReq struct {
	Manager    string   `json:"-"`
	NeedRepros bool     `json:"need_repros,omitempty"`
	Repros     [][]byte `json:"repros,omitempty"`
}

// SyncResp contains programs, reproducers, and remaining pending count from syz-hub.
type SyncResp struct {
	Inputs []Input  `json:"inputs,omitempty"`
	Repros [][]byte `json:"repros,omitempty"`
	More   int      `json:"more,omitempty"`
}

// Client communicates with a syz-hub server over HTTP.
type Client struct {
	client     string
	addr       string
	key        string
	httpClient *http.Client
	tokenCache *auth.TokenCache
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient overrides the default HTTP client used by Client
// (including GCE metadata token requests when key is empty).
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// NewClient constructs a syz-hub HTTP client for the given base URL and credentials.
// An empty key selects ambient GCE OAuth bearer token authentication via pkg/auth.
func NewClient(client, addr, key string, opts ...ClientOption) (*Client, error) {
	if client == "" {
		return nil, fmt.Errorf("hub client name is empty")
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid hub address %q: %w", addr, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid hub address %q: must be an http:// or https:// URL", addr)
	}
	if u.User != nil {
		return nil, fmt.Errorf("invalid hub address %q: credentials are not allowed in URL", addr)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("invalid hub address %q: query and fragment are not allowed", addr)
	}
	c := &Client{
		client: client,
		addr:   strings.TrimRight(addr, "/"),
		key:    key,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: 10 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("unexpected redirect")
			},
		}
	}
	if c.key == "" {
		tokenCache, err := auth.MakeCache(http.NewRequest, c.httpClient.Do)
		if err != nil {
			return nil, fmt.Errorf("init hub auth token cache: %w", err)
		}
		c.tokenCache = tokenCache
	}
	return c, nil
}

// Connect registers or re-registers a manager and its current corpus with syz-hub.
func (c *Client) Connect(ctx context.Context, req *ConnectReq) error {
	if req == nil {
		return fmt.Errorf("connect request is nil")
	}
	return c.postJSON(ctx, PathConnect, req.Manager, req, nil)
}

// Sync exchanges programs and reproducers with syz-hub.
func (c *Client) Sync(ctx context.Context, req *SyncReq) (*SyncResp, error) {
	if req == nil {
		return nil, fmt.Errorf("sync request is nil")
	}
	resp := new(SyncResp)
	if err := c.postJSON(ctx, PathSync, req.Manager, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) postJSON(ctx context.Context, path, manager string, reqBody, respBody any) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(reqBody); err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("compress request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+path, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set(HeaderClient, c.client)
	if manager != "" {
		req.Header.Set(HeaderManager, manager)
	}
	authHeader, err := c.authHeader()
	if err != nil {
		return fmt.Errorf("obtain auth header: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		const maxErrBody = 4096
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			return fmt.Errorf("request failed with %s", resp.Status)
		}
		return fmt.Errorf("request failed with %s: %s", resp.Status, msg)
	}

	if respBody == nil {
		return nil
	}
	const maxRespBody = 256 << 20
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRespBody)).Decode(respBody); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

func (c *Client) authHeader() (string, error) {
	if c.tokenCache != nil {
		return c.tokenCache.Get(time.Now())
	}
	return "Bearer " + c.key, nil
}
