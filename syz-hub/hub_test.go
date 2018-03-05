// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func TestAuth(t *testing.T) {
	hub := &Hub{
		keys: map[string]string{
			"foo": "1234",
			"bar": "abcd",
		},
	}
	tests := []struct {
		client  string
		key     string
		manager string
		result  string
		ok      bool
	}{
		{
			client:  "",
			key:     "",
			manager: "",
			result:  "",
			ok:      false,
		},
		{
			client:  "",
			key:     "1234",
			manager: "manager",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "123",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "abcd",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo",
			result:  "foo",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo-suffix",
			result:  "foo-suffix",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "",
			result:  "foo",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "bar",
			result:  "",
			ok:      false,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%q/%q/%q", test.client, test.key, test.manager), func(t *testing.T) {
			manager, err := hub.auth(test.client, test.key, test.manager)
			if !test.ok && err == nil {
				t.Fatalf("auth is expected to fail, but it did not")
			}
			if test.ok && err != nil {
				t.Fatalf("auth is not expected to fail, but it did: %v", err)
			}
			if manager != test.result {
				t.Fatalf("got bad manager %q, want %q", manager, test.result)
			}
		})
	}
}
