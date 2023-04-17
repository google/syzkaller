// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"regexp"
	"sort"
	"strings"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
)

type Thread struct {
	Subject   string
	MessageID string
	Type      dashapi.DiscussionType
	BugIDs    []string
	Messages  []*email.Email
}

// Threads extracts individual threads from a list of emails.
func Threads(emails []*email.Email) []*Thread {
	ctx := &parseCtx{
		messages: map[string]*email.Email{},
		next:     map[*email.Email][]*email.Email{},
	}
	for _, email := range emails {
		ctx.record(email)
	}
	ctx.process()
	return ctx.threads
}

// DiscussionType extracts the specific discussion type from an email.
func DiscussionType(msg *email.Email) dashapi.DiscussionType {
	discType := dashapi.DiscussionMention
	if msg.OwnEmail {
		discType = dashapi.DiscussionReport
	}
	// This is very crude, but should work for now.
	if patchSubjectRe.MatchString(strings.ToLower(msg.Subject)) {
		discType = dashapi.DiscussionPatch
	} else if strings.Contains(msg.Subject, "Monthly") {
		discType = dashapi.DiscussionReminder
	}
	return discType
}

var patchSubjectRe = regexp.MustCompile(`\[(?:(?:rfc|resend)\s+)*patch`)

type parseCtx struct {
	threads  []*Thread
	messages map[string]*email.Email
	next     map[*email.Email][]*email.Email
}

func (c *parseCtx) record(msg *email.Email) {
	c.messages[msg.MessageID] = msg
}

func (c *parseCtx) process() {
	// List messages for which we dont't have ancestors.
	nodes := []*email.Email{}
	for _, msg := range c.messages {
		if msg.InReplyTo == "" || c.messages[msg.InReplyTo] == nil {
			nodes = append(nodes, msg)
		} else {
			parent := c.messages[msg.InReplyTo]
			c.next[parent] = append(c.next[parent], msg)
		}
	}
	// Iterate starting from these tree nodes.
	for _, node := range nodes {
		c.visit(node, nil)
	}
	// Collect BugIDs.
	for _, thread := range c.threads {
		unique := map[string]struct{}{}
		for _, msg := range thread.Messages {
			for _, id := range msg.BugIDs {
				unique[id] = struct{}{}
			}
		}
		var ids []string
		for id := range unique {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		thread.BugIDs = ids
	}
}

func (c *parseCtx) visit(msg *email.Email, thread *Thread) {
	var oldInfo *email.OldThreadInfo
	if thread != nil {
		oldInfo = &email.OldThreadInfo{
			ThreadType: thread.Type,
		}
	}
	msgType := DiscussionType(msg)
	switch email.NewMessageAction(msg, msgType, oldInfo) {
	case email.ActionIgnore:
		thread = nil
	case email.ActionAppend:
		thread.Messages = append(thread.Messages, msg)
	case email.ActionNewThread:
		thread = &Thread{
			MessageID: msg.MessageID,
			Subject:   msg.Subject,
			Type:      msgType,
			Messages:  []*email.Email{msg},
		}
		c.threads = append(c.threads, thread)
	}
	for _, nextMsg := range c.next[msg] {
		c.visit(nextMsg, thread)
	}
}
