// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"github.com/google/syzkaller/pkg/email"
)

type Thread struct {
	Subject   string
	MessageID string
	BugIDs    []string
	Messages  []*email.Email
}

// Threads extracts individual threads from a list of emails.
func Threads(emails []*email.Email) []*Thread {
	ctx := &parseCtx{
		messages: map[string]*email.Email{},
	}
	for _, email := range emails {
		ctx.record(email)
	}
	return ctx.threads()
}

type parseCtx struct {
	messages map[string]*email.Email
}

func (c *parseCtx) record(msg *email.Email) {
	c.messages[msg.MessageID] = msg
}

func (c *parseCtx) threads() []*Thread {
	threads := map[string]*Thread{}
	threadsList := []*Thread{}
	// Detect threads, i.e. messages without In-Reply-To.
	for _, msg := range c.messages {
		if msg.InReplyTo == "" {
			thread := &Thread{
				MessageID: msg.MessageID,
				Subject:   msg.Subject,
			}
			threads[msg.MessageID] = thread
			threadsList = append(threadsList, thread)
		}
	}
	// Assign messages to threads.
	for _, msg := range c.messages {
		base := c.first(msg)
		if base == nil {
			continue
		}
		thread := threads[base.MessageID]
		thread.BugIDs = append(thread.BugIDs, msg.BugIDs...)
		thread.Messages = append(threads[base.MessageID].Messages, msg)
	}
	// Deduplicate BugIDs lists.
	for _, thread := range threads {
		if len(thread.BugIDs) == 0 {
			continue
		}
		unique := map[string]struct{}{}
		newList := []string{}
		for _, id := range thread.BugIDs {
			if _, ok := unique[id]; !ok {
				newList = append(newList, id)
			}
			unique[id] = struct{}{}
		}
		thread.BugIDs = newList
	}
	return threadsList
}

// first finds the firt message of an email thread.
func (c *parseCtx) first(msg *email.Email) *email.Email {
	visited := map[*email.Email]struct{}{}
	for {
		// There have been a few cases when we'd otherwise get an infinite loop.
		if _, ok := visited[msg]; ok {
			return nil
		}
		visited[msg] = struct{}{}
		if msg.InReplyTo == "" {
			return msg
		}
		msg = c.messages[msg.InReplyTo]
		if msg == nil {
			// Probably we just didn't load the message.
			return nil
		}
	}
}
