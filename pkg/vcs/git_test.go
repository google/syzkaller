// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGitParseCommit(t *testing.T) {
	tests := map[string]*Commit{
		`2075b16e32c26e4031b9fd3cbe26c54676a8fcb5
rbtree: include rcu.h
foobar@foobar.de
Foo Bar
Fri May 11 16:02:14 2018 -0700
Since commit c1adf20052d8 ("Introduce rb_replace_node_rcu()")
rbtree_augmented.h uses RCU related data structures but does not include
the header file.  It works as long as it gets somehow included before
that and fails otherwise.

Link: http://lkml.kernel.org/r/20180504103159.19938-1-bigeasy@linutronix.de
Signed-off-by: Foo Bad Baz <another@email.de>
Reviewed-by: <yetanother@email.org>
Cc: Unrelated Guy <somewhere@email.com>
Acked-by: Subsystem reviewer <Subsystem@reviewer.com>
Reported-and-tested-by: and@me.com
Reported-and-Tested-by: Name-name <name@name.com>
Tested-by: Must be correct <mustbe@correct.com>
Signed-off-by: Linux Master <linux@linux-foundation.org>
`: {
			Hash:       "2075b16e32c26e4031b9fd3cbe26c54676a8fcb5",
			Title:      "rbtree: include rcu.h",
			Author:     "foobar@foobar.de",
			AuthorName: "Foo Bar",
			CC: []string{
				"and@me.com",
				"another@email.de",
				"foobar@foobar.de",
				"linux@linux-foundation.org",
				"mustbe@correct.com",
				"name@name.com",
				"subsystem@reviewer.com",
				"yetanother@email.org",
			},
			Date: time.Date(2018, 5, 11, 16, 02, 14, 0, time.FixedZone("", -7*60*60)),
		},
	}
	for input, com := range tests {
		res, err := gitParseCommit([]byte(input), nil, nil, nil)
		if err != nil && com != nil {
			t.Fatalf("want %+v, got error: %v", com, err)
		}
		if err == nil && com == nil {
			t.Fatalf("want error, got commit %+v", res)
		}
		if com == nil {
			continue
		}
		if com.Hash != res.Hash {
			t.Fatalf("want hash %q, got %q", com.Hash, res.Hash)
		}
		if com.Title != res.Title {
			t.Fatalf("want title %q, got %q", com.Title, res.Title)
		}
		if com.Author != res.Author {
			t.Fatalf("want author %q, got %q", com.Author, res.Author)
		}
		if diff := cmp.Diff(com.CC, res.CC); diff != "" {
			t.Fatalf("bad CC: %v", diff)
		}
		if !com.Date.Equal(res.Date) {
			t.Fatalf("want date %v, got %v", com.Date, res.Date)
		}
	}
}

func TestGitParseReleaseTags(t *testing.T) {
	input := `
v3.1
v2.6.12
v2.6.39
v3.0
v3.10
v2.6.13
v3.11
v3.19
v3.9
v3.2
v4.9
v2.6.32
v4.0
voo
v1.foo
v10.2.foo
v1.2.
v1.
`
	want := []string{
		"v4.9",
		"v4.0",
		"v3.19",
		"v3.11",
		"v3.10",
		"v3.9",
		"v3.2",
		"v3.1",
		"v3.0",
		"v2.6.39",
		"v2.6.32",
		"v2.6.13",
		"v2.6.12",
	}
	got, err := gitParseReleaseTags([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got bad tags\ngot:  %+v\nwant: %+v", got, want)
	}
}
