// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reponseFor(t *testing.T, claims jwtClaims) (*httptest.Server, Endpoint) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, err := json.Marshal(jwtClaimsParse{
			Subject:    claims.Subject,
			Audience:   claims.Audience,
			Expiration: fmt.Sprint(claims.Expiration.Unix()),
		})
		if err != nil {
			t.Fatalf("Marshal %v", err)
		}
		w.Header()["Content-Type"] = []string{"application/json"}
		w.Write(bytes)
	}))
	return ts, MakeEndpoint(ts.URL)
}

func TestBearerValid(t *testing.T) {
	tm := time.Now()
	magic := "ValidSubj"
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    magic,
		Audience:   DashboardAudience,
		Expiration: tm.AddDate(0, 0, 1),
	})
	defer ts.Close()

	got, err := dut.DetermineAuthSubj(tm, []string{"Bearer x"})
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !strings.HasSuffix(got, magic) {
		t.Errorf("Wrong subj %v not suffix of %v", magic, got)
	}
}

func TestBearerWrongAudience(t *testing.T) {
	tm := time.Now()
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    "irrelevant",
		Expiration: tm.AddDate(0, 0, 1),
		Audience:   "junk",
	})
	defer ts.Close()

	_, err := dut.DetermineAuthSubj(tm, []string{"Bearer x"})
	if !strings.HasPrefix(err.Error(), "unexpected audience") {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestBearerExpired(t *testing.T) {
	tm := time.Now()
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    "irrelevant",
		Expiration: tm.AddDate(0, 0, -1),
		Audience:   DashboardAudience,
	})
	defer ts.Close()

	_, err := dut.DetermineAuthSubj(tm, []string{"Bearer x"})
	if !strings.HasPrefix(err.Error(), "token past expiration") {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestMissingHeader(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{})
	defer ts.Close()
	got, err := dut.DetermineAuthSubj(time.Now(), []string{})
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestBadHeader(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{})
	defer ts.Close()
	got, err := dut.DetermineAuthSubj(time.Now(), []string{"bad"})
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestBadHttpStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	defer ts.Close()
	dut := MakeEndpoint(ts.URL)
	got, err := dut.DetermineAuthSubj(time.Now(), []string{"Bearer x"})
	if err == nil || !strings.HasSuffix(err.Error(), "400") || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}
