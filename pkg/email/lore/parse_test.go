// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/email"
)

func TestThreadsCollection(t *testing.T) {
	messages := []string{
		// <A-Base> <-- <A-Child-1> <-- <A-Child-1-1>.
		`Date: Sun, 7 May 2017 19:54:00 -0700
Subject: Thread A
Message-ID: <A-Base>
From: UserA <a@user.com>
Content-Type: text/plain


Some text`,
		`Date: Sun, 7 May 2017 19:55:00 -0700
Subject: Re: Thread A
Message-ID: <A-Child-1>
From: UserB <b@user.com>
To: UserA <a@user.com>
Content-Type: text/plain
In-Reply-To: <A-Base>


Some reply`,
		`Date: Sun, 7 May 2017 19:56:00 -0700
Subject: Re: Re: Thread A
Message-ID: <A-Child-1-1>
From: UserC <c@user.com>
To: UserA <a@user.com>, UserB <b@user.com>
Content-Type: text/plain
In-Reply-To: <A-Child-1>


Some reply (2)`,
		// <Bug> with two children: <Bug-Reply1>, <Bug-Reply2>.
		`Date: Sun, 7 May 2017 19:57:00 -0700
Subject: [syzbot] Some bug
Message-ID: <Bug>
From: syzbot <syzbot+4564456@bar.com>
Content-Type: text/plain


Bug report`,
		`Date: Sun, 7 May 2017 19:58:00 -0700
Subject: Re: [syzbot] Some bug
Message-ID: <Bug-Reply1>
From: UserC <c@user.com>
To: syzbot <syzbot+4564456@bar.com>
In-Reply-To: <Bug>
Content-Type: text/plain


Bug report reply`,
		`Date: Sun, 7 May 2017 19:58:01 -0700
Subject: Re: [syzbot] Some bug
Message-ID: <Bug-Reply2>
From: UserD <d@user.com>
To: syzbot <syzbot+4564456@bar.com>
In-Reply-To: <Bug>B
Content-Type: text/plain


Bug report reply 2`,
		// And one PATCH without replies.
		`Date: Sun, 7 May 2017 19:58:01 -0700
Subject: [PATCH] Some bug fixed
Message-ID: <Patch>
From: UserE <e@user.com>
Cc: syzbot <syzbot+12345@bar.com>
Content-Type: text/plain


Patch`,
	}

	zone := time.FixedZone("", -7*60*60)
	expected := map[string]*Thread{
		"<A-Base>": {
			Subject:   "Thread A",
			MessageID: "<A-Base>",
			Messages: []*email.Email{
				{
					MessageID: "<A-Base>",
					Subject:   "Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, zone),
					Author:    "a@user.com",
					Cc:        []string{"a@user.com"},
					Command:   email.CmdNone,
				},
				{
					MessageID: "<A-Child-1>",
					Subject:   "Re: Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 55, 0, 0, zone),
					Author:    "b@user.com",
					Cc:        []string{"a@user.com", "b@user.com"},
					InReplyTo: "<A-Base>",
					Command:   email.CmdNone,
				},
				{
					MessageID: "<A-Child-1-1>",
					Subject:   "Re: Re: Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 56, 0, 0, zone),
					Author:    "c@user.com",
					Cc:        []string{"a@user.com", "b@user.com", "c@user.com"},
					InReplyTo: "<A-Child-1>",
					Command:   email.CmdNone,
				},
			},
		},
		"<Bug>": {
			Subject:   "[syzbot] Some bug",
			MessageID: "<Bug>",
			BugIDs:    []string{"4564456"},
			Messages: []*email.Email{
				{
					MessageID: "<Bug>",
					BugIDs:    []string{"4564456"},
					Subject:   "[syzbot] Some bug",
					Date:      time.Date(2017, time.May, 7, 19, 57, 0, 0, zone),
					Author:    "syzbot@bar.com",
					Command:   email.CmdNone,
				},
				{
					MessageID: "<Bug-Reply1>",
					BugIDs:    []string{"4564456"},
					Subject:   "Re: [syzbot] Some bug",
					Date:      time.Date(2017, time.May, 7, 19, 58, 0, 0, zone),
					Author:    "c@user.com",
					Cc:        []string{"c@user.com"},
					InReplyTo: "<Bug>",
					Command:   email.CmdNone,
				},
			},
		},
		"<Patch>": {
			Subject:   "[PATCH] Some bug fixed",
			MessageID: "<Patch>",
			BugIDs:    []string{"12345"},
			Messages: []*email.Email{
				{
					MessageID: "<Patch>",
					BugIDs:    []string{"12345"},
					Subject:   "[PATCH] Some bug fixed",
					Date:      time.Date(2017, time.May, 7, 19, 58, 1, 0, zone),
					Author:    "e@user.com",
					Cc:        []string{"e@user.com"},
					Command:   email.CmdNone,
				},
			},
		},
	}

	emails := []*email.Email{}
	for _, m := range messages {
		msg, err := email.Parse(strings.NewReader(m), []string{"syzbot@bar.com"},
			[]string{}, []string{"bar.com"})
		if err != nil {
			t.Fatal(err)
		}
		msg.Body = ""
		emails = append(emails, msg)
	}

	threads := Threads(emails)
	for _, d := range threads {
		sort.Slice(d.Messages, func(i, j int) bool {
			return d.Messages[i].Date.Before(d.Messages[j].Date)
		})
		if diff := cmp.Diff(expected[d.MessageID], d); diff != "" {
			t.Fatalf("%s: %s", d.MessageID, diff)
		}
	}

	if len(threads) != len(expected) {
		t.Fatalf("Expected %d threads, got %d", len(expected), len(threads))
	}
}
