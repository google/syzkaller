// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/syzkaller/dashboard/dashapi"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reponseFor(t *testing.T, claims jwtClaims) (*httptest.Server, authEndpoint) {
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
	return ts, mkAuthEndpoint(ts.URL)
}

func TestBearerValid(t *testing.T) {
	magic := "ValidSubj"
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    magic,
		Audience:   dashapi.DashboardAudience,
		Expiration: time.Now().AddDate(0, 0, 1),
	})
	defer ts.Close()

	got, err := dut.determineAuthSubj([]string{"Bearer x"})
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if !strings.HasSuffix(got, magic) {
		t.Errorf("Wrong subj %v not suffix of %v", magic, got)
	}
}

func TestBearerWrongAudience(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    "irrelevant",
		Expiration: time.Now().AddDate(0, 0, 1),
		Audience:   "junk",
	})
	defer ts.Close()

	_, err := dut.determineAuthSubj([]string{"Bearer x"})
	if !strings.HasPrefix(err.Error(), "unexpected audience") {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestBearerExpired(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{
		Subject:    "irrelevant",
		Expiration: time.Now().AddDate(0, 0, -1),
		Audience:   dashapi.DashboardAudience,
	})
	defer ts.Close()

	_, err := dut.determineAuthSubj([]string{"Bearer x"})
	if !strings.HasPrefix(err.Error(), "token past expiration") {
		t.Fatalf("Unexpected error %v", err)
	}
}

func TestMissingHeader(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{})
	defer ts.Close()
	got, err := dut.determineAuthSubj([]string{})
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestBadHeader(t *testing.T) {
	ts, dut := reponseFor(t, jwtClaims{})
	defer ts.Close()
	got, err := dut.determineAuthSubj([]string{"bad"})
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientSecretOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "secr1t", "")
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientOauthOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "OauthSubject:public",
		},
	}, "user", "", "OauthSubject:public")
	if err != nil || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientSecretFail(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{
			"user": "secr1t",
		},
	}, "user", "wrong", "")
	if err != ErrAccess || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientSecretMissing(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Clients: map[string]string{},
	}, "user", "ignored", "")
	if err != ErrAccess || got != "" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}

func TestClientNamespaceOK(t *testing.T) {
	got, err := checkClient(&GlobalConfig{
		Namespaces: map[string]*Config{
			"ns1": {
				Clients: map[string]string{
					"user": "secr1t",
				},
			},
		},
	}, "user", "secr1t", "")
	if err != nil || got != "ns1" {
		t.Errorf("Unexpected error %v %v", got, err)
	}
}
