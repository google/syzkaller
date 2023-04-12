// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestMessageActions(t *testing.T) {
	tests := []struct {
		name      string
		msg       *Email
		msgType   dashapi.DiscussionType
		oldThread *OldThreadInfo
		result    MessageAction
	}{
		{
			name:      "plain new thread",
			msg:       &Email{},
			msgType:   dashapi.DiscussionReport,
			oldThread: nil,
			result:    ActionNewThread,
		},
		{
			name: "plain reply to a report",
			msg: &Email{
				InReplyTo: "<abcd>",
			},
			msgType: dashapi.DiscussionReport,
			oldThread: &OldThreadInfo{
				ThreadType: dashapi.DiscussionReport,
			},
			result: ActionAppend,
		},
		{
			name: "plain reply to a patch",
			msg: &Email{
				InReplyTo: "<abcd>",
			},
			msgType: dashapi.DiscussionReport,
			oldThread: &OldThreadInfo{
				ThreadType: dashapi.DiscussionPatch,
			},
			result: ActionAppend,
		},
		{
			name: "sudden syzbot reply",
			msg: &Email{
				OwnEmail:  true,
				InReplyTo: "<abcd>",
			},
			msgType:   dashapi.DiscussionReport,
			oldThread: nil,
			result:    ActionIgnore,
		},
		{
			name: "legit subdiscussion",
			msg: &Email{
				InReplyTo: "<abcd>",
			},
			msgType:   dashapi.DiscussionReport,
			oldThread: nil,
			result:    ActionNewThread,
		},
		{
			name: "patch reply to report",
			msg: &Email{
				InReplyTo: "<abcd>",
			},
			msgType: dashapi.DiscussionPatch,
			oldThread: &OldThreadInfo{
				ThreadType: dashapi.DiscussionReport,
			},
			result: ActionNewThread,
		},
	}
	for _, _test := range tests {
		test := _test
		t.Run(test.name, func(tt *testing.T) {
			got := NewMessageAction(test.msg, test.msgType, test.oldThread)
			if got != test.result {
				t.Fatalf("wanted %v, got %v", test.result, got)
			}
		})
	}
}
