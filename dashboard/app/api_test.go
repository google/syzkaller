// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
)

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
