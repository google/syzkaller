// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/stretchr/testify/assert"
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
		// An orphaned reply from a human.
		`Date: Sun, 7 May 2017 19:57:00 -0700
Subject: Another bug discussion
In-Reply-To: <Unknown>
Message-ID: <Sub-Discussion>
From: person@email.com
Cc: syzbot <syzbot+4564456@bar.com>
Content-Type: text/plain


Bug report`,
		// An orphaned reply from a bot.
		`Date: Sun, 7 May 2017 19:57:00 -0700
Subject: Re: [syzbot] Some bug 3
In-Reply-To: <Unknown>
Message-ID: <Sub-Discussion-Bot>
From: syzbot+4564456@bar.com
To: all@email.com
Content-Type: text/plain


Bug report`,
	}

	zone := time.FixedZone("", -7*60*60)
	expected := map[string]*Thread{
		"<A-Base>": {
			Subject:   "Thread A",
			MessageID: "<A-Base>",
			Type:      dashapi.DiscussionMention,
			Messages: []*email.Email{
				{
					MessageID: "<A-Base>",
					Subject:   "Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 54, 0, 0, zone),
					Author:    "a@user.com",
					Cc:        []string{"a@user.com"},
				},
				{
					MessageID: "<A-Child-1>",
					Subject:   "Re: Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 55, 0, 0, zone),
					Author:    "b@user.com",
					Cc:        []string{"a@user.com", "b@user.com"},
					InReplyTo: "<A-Base>",
				},
				{
					MessageID: "<A-Child-1-1>",
					Subject:   "Re: Re: Thread A",
					Date:      time.Date(2017, time.May, 7, 19, 56, 0, 0, zone),
					Author:    "c@user.com",
					Cc:        []string{"a@user.com", "b@user.com", "c@user.com"},
					InReplyTo: "<A-Child-1>",
				},
			},
		},
		"<Bug>": {
			Subject:   "[syzbot] Some bug",
			MessageID: "<Bug>",
			Type:      dashapi.DiscussionReport,
			BugIDs:    []string{"4564456"},
			Messages: []*email.Email{
				{
					MessageID: "<Bug>",
					BugIDs:    []string{"4564456"},
					Subject:   "[syzbot] Some bug",
					Date:      time.Date(2017, time.May, 7, 19, 57, 0, 0, zone),
					Author:    "syzbot@bar.com",
					OwnEmail:  true,
				},
				{
					MessageID: "<Bug-Reply1>",
					BugIDs:    []string{"4564456"},
					Subject:   "Re: [syzbot] Some bug",
					Date:      time.Date(2017, time.May, 7, 19, 58, 0, 0, zone),
					Author:    "c@user.com",
					Cc:        []string{"c@user.com"},
					InReplyTo: "<Bug>",
				},
				{
					MessageID: "<Bug-Reply2>",
					BugIDs:    []string{"4564456"},
					Subject:   "Re: [syzbot] Some bug",
					Date:      time.Date(2017, time.May, 7, 19, 58, 1, 0, zone),
					Author:    "d@user.com",
					Cc:        []string{"d@user.com"},
					InReplyTo: "<Bug>",
				},
			},
		},
		"<Patch>": {
			Subject:   "[PATCH] Some bug fixed",
			MessageID: "<Patch>",
			Type:      dashapi.DiscussionPatch,
			BugIDs:    []string{"12345"},
			Messages: []*email.Email{
				{
					MessageID: "<Patch>",
					BugIDs:    []string{"12345"},
					Subject:   "[PATCH] Some bug fixed",
					Date:      time.Date(2017, time.May, 7, 19, 58, 1, 0, zone),
					Author:    "e@user.com",
					Cc:        []string{"e@user.com"},
				},
			},
		},
		"<Sub-Discussion>": {
			Subject:   "Another bug discussion",
			MessageID: "<Sub-Discussion>",
			Type:      dashapi.DiscussionMention,
			BugIDs:    []string{"4564456"},
			Messages: []*email.Email{
				{
					MessageID: "<Sub-Discussion>",
					InReplyTo: "<Unknown>",
					Date:      time.Date(2017, time.May, 7, 19, 57, 0, 0, zone),
					BugIDs:    []string{"4564456"},
					Cc:        []string{"person@email.com"},
					Subject:   "Another bug discussion",
					Author:    "person@email.com",
				},
			},
		},
		"<Sub-Discussion-Bot>": nil,
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
	got := map[string]*Thread{}

	for _, d := range threads {
		sort.Slice(d.Messages, func(i, j int) bool {
			return d.Messages[i].Date.Before(d.Messages[j].Date)
		})
		got[d.MessageID] = d
	}

	for key, val := range expected {
		if diff := cmp.Diff(val, got[key]); diff != "" {
			t.Fatalf("%s: %s", key, diff)
		}
	}

	if len(threads) > len(expected) {
		t.Fatalf("expected %d threads, got %d", len(expected), len(threads))
	}
}

func TestParsePatchSubject(t *testing.T) {
	tests := []struct {
		subj string
		ret  PatchSubject
	}{
		{
			subj: `[PATCH] abcd`,
			ret:  PatchSubject{Title: "abcd"},
		},
		{
			subj: `[PATCH 00/20] abcd`,
			ret:  PatchSubject{Title: "abcd", Seq: value[int](0), Total: value[int](20)},
		},
		{
			subj: `[PATCH 5/6] abcd`,
			ret:  PatchSubject{Title: "abcd", Seq: value[int](5), Total: value[int](6)},
		},
		{
			subj: `[PATCH RFC v3 0/4] abcd`,
			ret: PatchSubject{
				Title:   "abcd",
				Tags:    []string{"RFC"},
				Version: value[int](3),
				Seq:     value[int](0),
				Total:   value[int](4),
			},
		},
		{
			subj: `[RFC PATCH] abcd`,
			ret:  PatchSubject{Title: "abcd", Tags: []string{"RFC"}},
		},
		{
			subj: `[PATCH net-next v2 00/21] abcd`,
			ret: PatchSubject{
				Title:   "abcd",
				Tags:    []string{"net-next"},
				Version: value[int](2),
				Seq:     value[int](0),
				Total:   value[int](21),
			},
		},
		{
			subj: `[PATCH v2 RESEND] abcd`,
			ret:  PatchSubject{Title: "abcd", Version: value[int](2), Tags: []string{"RESEND"}},
		},
		{
			subj: `[PATCH RFC net-next v3 05/21] abcd`,
			ret: PatchSubject{
				Title:   "abcd",
				Tags:    []string{"RFC", "net-next"},
				Version: value[int](3),
				Seq:     value[int](5),
				Total:   value[int](21),
			},
		},
	}
	for id, test := range tests {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			ret, ok := parsePatchSubject(test.subj)
			assert.True(t, ok)
			assert.Equal(t, test.ret, ret)
		})
	}
}

func TestDiscussionType(t *testing.T) {
	tests := []struct {
		msg *email.Email
		ret dashapi.DiscussionType
	}{
		{
			msg: &email.Email{
				Subject: "[PATCH] Bla-bla",
			},
			ret: dashapi.DiscussionPatch,
		},
		{
			msg: &email.Email{
				Subject: "[patch v3] Bla-bla",
			},
			ret: dashapi.DiscussionPatch,
		},
		{
			msg: &email.Email{
				Subject: "[RFC PATCH] Bla-bla",
			},
			ret: dashapi.DiscussionPatch,
		},
		{
			msg: &email.Email{
				Subject: "[RESEND PATCH] Bla-bla",
			},
			ret: dashapi.DiscussionPatch,
		},
		{
			msg: &email.Email{
				Subject:  "[syzbot] Monthly ext4 report",
				OwnEmail: true,
			},
			ret: dashapi.DiscussionReminder,
		},
		{
			msg: &email.Email{
				Subject:  "[syzbot] WARNING in abcd",
				OwnEmail: true,
			},
			ret: dashapi.DiscussionReport,
		},
		{
			msg: &email.Email{
				Subject: "Some human-reported bug",
			},
			ret: dashapi.DiscussionMention,
		},
	}
	for _, test := range tests {
		got := DiscussionType(test.msg)
		if got != test.ret {
			t.Fatalf("expected %v got %v for %v", test.ret, got, test.msg)
		}
	}
}

func TestParseSeries(t *testing.T) {
	messages := []string{
		// A simple patch series.
		`Date: Sun, 7 May 2017 19:54:00 -0700
Subject: [PATCH] Small patch
Message-ID: <First>
From: UserA <a@user.com>
Content-Type: text/plain


Some text`,
		// A series with a cover.
		`Date: Sun, 7 May 2017 19:55:00 -0700
Subject: [PATCH v2 00/02] A longer series
Message-ID: <Second>
From: UserB <b@user.com>
To: UserA <a@user.com>
Content-Type: text/plain

Some cover`,
		`Date: Sun, 7 May 2017 19:56:00 -0700
Subject: [PATCH v2 01/02] First patch
Message-ID: <Second-1>
From: UserC <c@user.com>
To: UserA <a@user.com>, UserB <b@user.com>
Content-Type: text/plain
In-Reply-To: <Second>


Patch 1/2`,
		`Date: Sun, 7 May 2017 19:56:00 -0700
Subject: [PATCH v2 02/02] Second patch
Message-ID: <Second-2>
From: UserC <c@user.com>
To: UserA <a@user.com>, UserB <b@user.com>
Content-Type: text/plain
In-Reply-To: <Second>


Patch 2/2`,
		// Missing patches.
		`Date: Sun, 7 May 2017 19:57:00 -0700
Subject: [PATCH 01/03] Series
Message-ID: <Third>
From: Someone <a@b.com>
Content-Type: text/plain

Bug report`,
	}

	emails := []*email.Email{}
	for _, m := range messages {
		msg, err := email.Parse(strings.NewReader(m), nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		emails = append(emails, msg)
	}

	series := PatchSeries(emails)
	assert.Len(t, series, 3)

	expectPerID := map[string]*Series{
		"<First>": {
			Subject: "Small patch",
			Version: 1,
			Patches: []Patch{
				{
					Seq:   1,
					Email: &email.Email{Subject: "[PATCH] Small patch"},
				},
			},
		},
		"<Second>": {
			Subject: "A longer series",
			Version: 2,
			Patches: []Patch{
				{
					Seq:   1,
					Email: &email.Email{Subject: "[PATCH v2 01/02] First patch"},
				},
				{
					Seq:   2,
					Email: &email.Email{Subject: "[PATCH v2 02/02] Second patch"},
				},
			},
		},
		"<Third>": {
			Subject:   "Series",
			Version:   1,
			Corrupted: "the subject mentions 3 patches, 1 are found",
			Patches: []Patch{
				{
					Seq:   1,
					Email: &email.Email{Subject: "[PATCH 01/03] Series"},
				},
			},
		},
	}
	for _, s := range series {
		expect := expectPerID[s.MessageID]
		if expect == nil {
			t.Fatalf("unexpected message: %q", s.MessageID)
		}
		expectPerID[s.MessageID] = nil
		t.Run(s.MessageID, func(t *testing.T) {
			assert.Equal(t, expect.Corrupted, s.Corrupted, "corrupted differs")
			assert.Equal(t, expect.Subject, s.Subject, "subject differs")
			assert.Equal(t, expect.Version, s.Version, "version differs")
			assert.Len(t, s.Patches, len(expect.Patches), "patch count differs")
			for i, expectPatch := range expect.Patches {
				got := s.Patches[i]
				assert.Equal(t, expectPatch.Seq, got.Seq, "seq differs")
			}
		})
	}
}
