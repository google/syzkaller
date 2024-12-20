// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

type Series struct {
	Subject   string
	MessageID string
	Version   int
	Total     int
	Corrupted string // If non-empty, contains a reason why the series better be ignored.
	Patches   []Patch
	// TODO: add Cover *email.Email?
}

type Patch struct {
	Seq int
	*email.Email
}

// Threads extracts individual threads from a list of emails.
func Threads(emails []*email.Email) []*Thread {
	return listThreads(emails, 0)
}

func listThreads(emails []*email.Email, maxDepth int) []*Thread {
	ctx := &parseCtx{
		maxDepth: maxDepth,
		messages: map[string]*email.Email{},
		next:     map[*email.Email][]*email.Email{},
	}
	for _, email := range emails {
		ctx.record(email)
	}
	ctx.process()
	return ctx.threads
}

// PatchSeries is similar to Threads, but returns only the patch series submitted to the mailing lists.
// TODO: add a test?
func PatchSeries(emails []*email.Email) []*Series {
	var ret []*Series
	// Normally, all following series patches are sent in response to the first email sent.
	// So there's no sense to look at deeper replies.
	for _, thread := range listThreads(emails, 1) {
		if thread.Type != dashapi.DiscussionPatch {
			continue
		}
		patch, ok := parsePatchSubject(thread.Subject)
		if !ok {
			// It must never be happening.
			panic("DiscussionPatch is set, but we fail to parse the thread subject")
		}
		series := &Series{
			Subject:   patch.Title,
			MessageID: thread.MessageID,
			Total:     1,
			Version:   1,
		}
		if patch.Total.IsSet() {
			series.Total = patch.Total.Value()
		}
		if patch.Version.IsSet() {
			series.Version = patch.Version.Value()
		}
		ret = append(ret, series)
		if patch.Seq.IsSet() && patch.Seq.Value() > 1 {
			series.Corrupted = "the first patch has seq>1"
			continue
		}
		hasSeq := map[int]bool{}
		for _, email := range thread.Messages {
			patch, ok := parsePatchSubject(email.Subject)
			if !ok {
				continue
			}
			seq := 1
			if patch.Seq.IsSet() {
				seq = patch.Seq.Value()
			}
			if seq == 0 {
				// The cover email is not of interest.
				continue
			}
			if hasSeq[seq] {
				// It's weird if that really happens, but let's skip for now.
				continue
			}
			hasSeq[seq] = true
			series.Patches = append(series.Patches, Patch{
				Seq:   seq,
				Email: email,
			})
		}
		if len(hasSeq) != series.Total {
			series.Corrupted = fmt.Sprintf("the subject mentions %d patches, %d are found",
				series.Total, len(hasSeq))
			continue
		}
		if len(series.Patches) == 0 {
			series.Corrupted = fmt.Sprintf("0 patches")
			continue
		}
		sort.Slice(series.Patches, func(i, j int) bool {
			return series.Patches[i].Seq < series.Patches[j].Seq
		})
	}
	return ret
}

// DiscussionType extracts the specific discussion type from an email.
func DiscussionType(msg *email.Email) dashapi.DiscussionType {
	discType := dashapi.DiscussionMention
	if msg.OwnEmail {
		discType = dashapi.DiscussionReport
	}
	// This is very crude, but should work for now.
	if _, ok := parsePatchSubject(msg.Subject); ok {
		discType = dashapi.DiscussionPatch
	} else if strings.Contains(msg.Subject, "Monthly") {
		discType = dashapi.DiscussionReminder
	}
	return discType
}

type PatchSubject struct {
	Title   string
	Tags    []string // Sometimes there's e.g. "net" or "next-next" in the subject.
	Version Optional[int]
	Seq     Optional[int] // The "Seq/Total" part.
	Total   Optional[int]
}

var patchSubjectRe = regexp.MustCompile(`(?mi)^\[(?:([\w\s-]+)\s)?PATCH(?:\s([\w\s-]+))??(?:\s0*(\d+)\/(\d+))?\]\s*(.+)`)

func parsePatchSubject(subject string) (PatchSubject, bool) {
	var ret PatchSubject
	groups := patchSubjectRe.FindStringSubmatch(subject)
	if len(groups) == 0 {
		return ret, false
	}
	tags := strings.Fields(groups[1])
	for _, tag := range append(tags, strings.Fields(groups[2])...) {
		if strings.HasPrefix(tag, "v") {
			val, err := strconv.Atoi(strings.TrimPrefix(tag, "v"))
			if err == nil {
				ret.Version.Set(val)
				continue
			}
		}
		ret.Tags = append(ret.Tags, tag)
	}
	sort.Strings(ret.Tags)
	if groups[3] != "" {
		if val, err := strconv.Atoi(groups[3]); err == nil {
			ret.Seq.Set(val)
		}
	}
	if groups[4] != "" {
		if val, err := strconv.Atoi(groups[4]); err == nil {
			ret.Total.Set(val)
		}
	}
	ret.Title = groups[5]
	return ret, true
}

type parseCtx struct {
	maxDepth int
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
		c.visit(node, nil, 0)
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

func (c *parseCtx) visit(msg *email.Email, thread *Thread, depth int) {
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
	if c.maxDepth == 0 || depth < c.maxDepth {
		for _, nextMsg := range c.next[msg] {
			c.visit(nextMsg, thread, depth+1)
		}
	}
}

type Optional[T any] struct {
	val T
	set bool
}

func value[T any](val T) Optional[T] {
	return Optional[T]{val: val, set: true}
}

func (o Optional[T]) IsSet() bool {
	return o.set
}

func (o Optional[T]) Value() T {
	return o.val
}

func (o *Optional[T]) Set(val T) {
	o.val = val
	o.set = true
}
