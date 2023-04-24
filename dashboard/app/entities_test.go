// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	db "google.golang.org/appengine/v2/datastore"
)

func TestOldBugTagsConversion(t *testing.T) {
	oldBug := &struct {
		Namespace string
		Title     string
		Tags      BugTags202304
	}{
		Namespace: "some-ns",
		Title:     "some title",
		Tags: BugTags202304{
			Subsystems: []BugTag202304{
				{
					Name:  "first",
					SetBy: "user",
				},
				{
					Name: "second",
				},
			},
		},
	}

	fields, err := db.SaveStruct(oldBug)
	if err != nil {
		t.Fatal(err)
	}

	newBug := &Bug{}
	err = newBug.Load(fields)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(&Bug{
		Namespace: "some-ns",
		Title:     "some title",
		Labels: []BugLabel{
			{
				Value: "first",
				SetBy: "user",
				Label: SubsystemLabel,
			},
			{
				Value: "second",
				Label: SubsystemLabel,
			},
		},
	}, newBug); diff != "" {
		t.Fatal(diff)
	}
}
