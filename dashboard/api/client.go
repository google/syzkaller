// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

type Client struct {
	url      string
	token    string
	throttle bool
	ctor     requestCtor
	doer     requestDoer
}

// accessToken is OAuth access token obtained with "gcloud auth print-access-token"
// (provided your account has at least user level access to the dashboard).
// If the token is provided, dashboard should disable API throttling.
// The token can be empty, in which case the dashboard may throttle requests.
func NewClient(dashboardURL, accessToken string) *Client {
	return &Client{
		url:      strings.TrimSuffix(dashboardURL, "/"),
		token:    accessToken,
		throttle: true,
		ctor:     http.NewRequest,
		doer:     http.DefaultClient.Do,
	}
}

type (
	requestCtor func(method, url string, body io.Reader) (*http.Request, error)
	requestDoer func(req *http.Request) (*http.Response, error)
)

func NewTestClient(ctor requestCtor, doer requestDoer) *Client {
	return &Client{
		url:  "http://localhost",
		ctor: ctor,
		doer: doer,
	}
}

type BugGroupType int

const (
	BugGroupOpen BugGroupType = 1 << iota
	BugGroupFixed
	BugGroupInvalid
	BugGroupAll = ^0
)

var groupSuffix = map[BugGroupType]string{
	BugGroupFixed:   "/fixed",
	BugGroupInvalid: "/invalid",
}

func (c *Client) BugGroups(ns string, groups BugGroupType) ([]BugSummary, error) {
	var bugs []BugSummary
	for _, typ := range []BugGroupType{BugGroupOpen, BugGroupFixed, BugGroupInvalid} {
		if (groups & typ) == 0 {
			continue
		}
		url := "/" + ns + groupSuffix[typ]
		var group BugGroup
		if err := c.query(url, &group); err != nil {
			return nil, err
		}
		bugs = append(bugs, group.Bugs...)
	}
	return bugs, nil
}

func (c *Client) Bug(link string) (*Bug, error) {
	bug := new(Bug)
	return bug, c.query(link, bug)
}

func (c *Client) Text(query string) ([]byte, error) {
	queryURL, err := c.queryURL(query)
	if err != nil {
		return nil, err
	}
	req, err := c.ctor(http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	if c.token != "" {
		req.Header.Add("Authorization", "Bearer "+c.token)
	} else if c.throttle {
		<-throttler
	}
	res, err := c.doer(req)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%v): %w", queryURL, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 || err != nil {
		return nil, fmt.Errorf("api request %q failed: status(%v) err(%w) body(%.1024s)",
			queryURL, res.StatusCode, err, string(body))
	}
	return body, nil
}

func (c *Client) query(query string, result any) error {
	data, err := c.Text(query)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("json.Unmarshal: %w\n%s", err, data)
	}
	if ver := reflect.ValueOf(result).Elem().FieldByName("Version").Int(); ver != Version {
		return fmt.Errorf("unsupported export version %v (expect %v)", ver, Version)
	}
	return nil
}

func (c *Client) queryURL(query string) (string, error) {
	// All links in API are html escaped for some reason, unescape them.
	query = c.url + html.UnescapeString(query)
	u, err := url.Parse(query)
	if err != nil {
		return "", fmt.Errorf("url.Parse(%v): %w", query, err)
	}
	vals := u.Query()
	// json=1 is ignored for text end points, so we don't bother not adding it.
	vals.Set("json", "1")
	u.RawQuery = vals.Encode()
	return u.String(), nil
}

var throttler = time.NewTicker(time.Second).C
