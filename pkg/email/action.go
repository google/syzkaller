// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import "github.com/google/syzkaller/dashboard/dashapi"

type OldThreadInfo struct {
	ThreadType dashapi.DiscussionType
}

type MessageAction string

const (
	ActionIgnore    MessageAction = "ignore"
	ActionAppend    MessageAction = "append"
	ActionNewThread MessageAction = "new-thread"
)

func NewMessageAction(msg *Email, msgType dashapi.DiscussionType, oldThread *OldThreadInfo) MessageAction {
	if msg.InReplyTo == "" {
		// If it's not a reply, always start a new thread.
		return ActionNewThread
	}
	if oldThread != nil {
		// Sometimes patches are sent as replies to the bug report.
		// In this case, we'd better report it as a new discussion.
		if msgType == dashapi.DiscussionPatch &&
			msgType != oldThread.ThreadType {
			return ActionNewThread
		}
		// Otherwise just append the message.
		return ActionAppend
	}
	if msg.OwnEmail {
		// Most likely it's a bot's public reply to a non-public
		// patch testing request. Ignore it.
		return ActionIgnore
	}
	// If the original discussion is not recorded anywhere, it means
	// we were likely only mentioned in some further discussion.
	// Remember then only the sub-thread visible to us.
	return ActionNewThread
}
