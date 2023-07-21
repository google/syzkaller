// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/v2/datastore"
)

// saveDiscussionMessage is meant to be called after each received E-mail message,
// for which we know the BugID.
func saveDiscussionMessage(c context.Context, msg *email.Email,
	msgSource dashapi.DiscussionSource, msgType dashapi.DiscussionType) error {
	discUpdate := &dashapi.Discussion{
		Source: msgSource,
		Type:   msgType,
		BugIDs: msg.BugIDs,
	}
	var parent *Discussion
	var oldThreadInfo *email.OldThreadInfo
	if msg.InReplyTo != "" {
		parent, _ = discussionByMessageID(c, msgSource, msg.InReplyTo)
		if parent != nil {
			oldThreadInfo = &email.OldThreadInfo{
				ThreadType: dashapi.DiscussionType(parent.Type),
			}
		}
	}
	switch email.NewMessageAction(msg, msgType, oldThreadInfo) {
	case email.ActionIgnore:
		return nil
	case email.ActionAppend:
		discUpdate.ID = parent.ID
		discUpdate.Type = oldThreadInfo.ThreadType
	case email.ActionNewThread:
		// Use the current message as the discussion's head.
		discUpdate.ID = msg.MessageID
		discUpdate.Subject = msg.Subject
	}
	discUpdate.Messages = append(discUpdate.Messages, dashapi.DiscussionMessage{
		ID:       msg.MessageID,
		Time:     msg.Date,
		External: !msg.OwnEmail,
	})
	return mergeDiscussion(c, discUpdate)
}

// mergeDiscussion either creates a new discussion or updates the existing one.
// It is assumed that the input is valid.
func mergeDiscussion(c context.Context, update *dashapi.Discussion) error {
	if len(update.Messages) == 0 {
		return fmt.Errorf("no messages")
	}
	newBugKeys, err := getBugKeys(c, update.BugIDs)
	if err != nil {
		return nil
	}
	// First update the discussion itself.
	d := new(Discussion)
	var diff DiscussionSummary
	tx := func(c context.Context) error {
		err := db.Get(c, discussionKey(c, string(update.Source), update.ID), d)
		if err != nil && err != db.ErrNoSuchEntity {
			return fmt.Errorf("failed to query Discussion: %w", err)
		} else if err == db.ErrNoSuchEntity {
			d.ID = update.ID
			d.Source = string(update.Source)
			d.Type = string(update.Type)
			d.Subject = update.Subject
		}
		d.BugKeys = unique(append(d.BugKeys, newBugKeys...))
		diff = d.addMessages(update.Messages)
		if d.Type == string(dashapi.DiscussionPatch) {
			diff.LastPatchMessage = diff.LastMessage
		}
		d.Summary.merge(diff)
		_, err = db.Put(c, d.key(c), d)
		if err != nil {
			return fmt.Errorf("failed to put Discussion: %w", err)
		}
		return nil
	}
	err = db.RunInTransaction(c, tx, &db.TransactionOptions{Attempts: 15, XG: true})
	if err != nil {
		return err
	}
	// Update individual bug statistics.
	// We have to do it outside of the main transaction, as we might hit the "operating on
	// too many entity groups in a single transaction." error.
	for _, key := range d.BugKeys {
		err := db.RunInTransaction(c, func(c context.Context) error {
			return mergeDiscussionSummary(c, key, d.Source, diff)
		}, &db.TransactionOptions{Attempts: 15})
		if err != nil {
			return fmt.Errorf("failed to put update summary for %s: %w", key, err)
		}
	}
	return nil
}

func mergeDiscussionSummary(c context.Context, key, source string, diff DiscussionSummary) error {
	bug := new(Bug)
	bugKey := db.NewKey(c, "Bug", key, 0, nil)
	if err := db.Get(c, bugKey, bug); err != nil {
		return fmt.Errorf("failed to get bug: %w", err)
	}
	var record *BugDiscussionInfo
	for i, item := range bug.DiscussionInfo {
		if item.Source == source {
			record = &bug.DiscussionInfo[i]
		}
	}
	if record == nil {
		bug.DiscussionInfo = append(bug.DiscussionInfo, BugDiscussionInfo{
			Source: source,
		})
		record = &bug.DiscussionInfo[len(bug.DiscussionInfo)-1]
	}
	record.Summary.merge(diff)
	if _, err := db.Put(c, bugKey, bug); err != nil {
		return fmt.Errorf("failed to put bug: %w", err)
	}
	return nil
}

func (ds *DiscussionSummary) merge(diff DiscussionSummary) {
	ds.AllMessages += diff.AllMessages
	ds.ExternalMessages += diff.ExternalMessages
	if ds.LastMessage.Before(diff.LastMessage) {
		ds.LastMessage = diff.LastMessage
	}
	if ds.LastPatchMessage.Before(diff.LastPatchMessage) {
		ds.LastPatchMessage = diff.LastPatchMessage
	}
}

func (bug *Bug) discussionSummary() DiscussionSummary {
	// TODO: if there ever appear any non-public DiscussionSource, we'll need to consider
	// their accessLevel as well.
	var ret DiscussionSummary
	for _, item := range bug.DiscussionInfo {
		ret.merge(item.Summary)
	}
	return ret
}

const maxMessagesInDiscussion = 1500

func (d *Discussion) addMessages(messages []dashapi.DiscussionMessage) DiscussionSummary {
	var diff DiscussionSummary
	existingIDs := d.messageIDs()
	for _, m := range messages {
		if _, ok := existingIDs[m.ID]; ok {
			continue
		}
		existingIDs[m.ID] = struct{}{}
		diff.AllMessages++
		if m.External {
			diff.ExternalMessages++
		}
		if diff.LastMessage.Before(m.Time) {
			diff.LastMessage = m.Time
		}
		d.Messages = append(d.Messages, DiscussionMessage{
			ID:       m.ID,
			External: m.External,
			Time:     m.Time,
		})
	}
	if len(d.Messages) == 0 {
		return diff
	}
	sort.Slice(d.Messages, func(i, j int) bool {
		return d.Messages[i].Time.Before(d.Messages[j].Time)
	})
	// Always keep the oldest message.
	first := d.Messages[0]
	if len(d.Messages) > maxMessagesInDiscussion {
		d.Messages = append([]DiscussionMessage{first},
			d.Messages[len(d.Messages)-maxMessagesInDiscussion+1:]...)
	}
	return diff
}

func (d *Discussion) messageIDs() map[string]struct{} {
	ret := map[string]struct{}{}
	for _, m := range d.Messages {
		ret[m.ID] = struct{}{}
	}
	return ret
}

func (d *Discussion) link() string {
	switch dashapi.DiscussionSource(d.Source) {
	case dashapi.DiscussionLore:
		return fmt.Sprintf("https://lore.kernel.org/all/%s/T/", strings.Trim(d.ID, "<>"))
	}
	return ""
}

func discussionByMessageID(c context.Context, source dashapi.DiscussionSource,
	msgID string) (*Discussion, error) {
	var discussions []*Discussion
	keys, err := db.NewQuery("Discussion").
		Filter("Source=", source).
		Filter("Messages.ID=", msgID).
		Limit(2).
		GetAll(c, &discussions)
	if err != nil {
		return nil, err
	} else if len(keys) == 0 {
		return nil, db.ErrNoSuchEntity
	} else if len(keys) == 2 {
		// TODO: consider merging discussions in this case.
		return nil, fmt.Errorf("message %s is present in several discussions", msgID)
	}
	return discussions[0], nil
}

func discussionsForBug(c context.Context, bugKey *db.Key) ([]*Discussion, error) {
	var discussions []*Discussion
	_, err := db.NewQuery("Discussion").
		Filter("BugKeys=", bugKey.StringID()).
		GetAll(c, &discussions)
	if err != nil {
		return nil, err
	}
	return discussions, nil
}

func getBugKeys(c context.Context, bugIDs []string) ([]string, error) {
	keys := []string{}
	for _, id := range bugIDs {
		_, bugKey, err := findBugByReportingID(c, id)
		if err != nil {
			return nil, fmt.Errorf("failed to find bug for %s: %w", id, err)
		}
		keys = append(keys, bugKey.StringID())
	}
	return keys, nil
}

func unique(items []string) []string {
	dup := map[string]struct{}{}
	ret := []string{}
	for _, item := range items {
		if _, ok := dup[item]; ok {
			continue
		}
		dup[item] = struct{}{}
		ret = append(ret, item)
	}
	return ret
}
