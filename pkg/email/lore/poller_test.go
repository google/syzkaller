// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPoller(t *testing.T) {
	repoDir := t.TempDir()
	loreArchive := NewTestLoreArchive(t, repoDir)

	output := make(chan *PolledEmail, 16)
	now := time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC)
	cfg := PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		OwnEmails: []string{"bot@syzbot.com"},
		now:       func() time.Time { return now },
	}

	poller, err := NewPoller(cfg)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Save some messages to build initial graph.
	t.Logf("saving initial messages")
	dateOldEmail := now.Add(-48 * time.Hour).Format(time.RFC1123Z)
	dateAEmail := now.Add(-2 * time.Hour).Format(time.RFC1123Z)
	dateBEmail := now.Add(-1 * time.Hour).Format(time.RFC1123Z)

	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Old Message
Message-ID: <old>
Content-Type: text/plain

`, dateOldEmail), now.Add(-48*time.Hour))

	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Root Message
Message-ID: <root>
Content-Type: text/plain

`, dateAEmail), now.Add(-2*time.Hour))

	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Reply to Root
Message-ID: <reply1>
In-Reply-To: <root>
Content-Type: text/plain

`, dateBEmail), now.Add(-1*time.Hour))

	// 2. Poll for the first time.
	t.Logf("first poll (initialize)")

	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	t.Logf("first poll (actual)")
	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	// Since it's the first poll and messages are within 24 hours (we didn't mock time, so they are fresh),
	// they should be pushed to the channel.

	msg1 := <-output
	parsed1 := msg1.Email
	assert.Equal(t, "<root>", parsed1.MessageID)
	assert.Equal(t, "<root>", msg1.RootMessageID)

	msg2 := <-output
	parsed2 := msg2.Email
	assert.Equal(t, "<reply1>", parsed2.MessageID)
	assert.Equal(t, "<root>", msg2.RootMessageID)

	// Verify no more messages (specifically '<old>') were pushed.
	select {
	case msg := <-output:
		parsed := msg.Email
		t.Errorf("unexpected message in channel: %s", parsed.MessageID)
	default:
		// OK
	}

	// 3. Save a new message (reply to reply1).
	t.Logf("saving new message")
	dateCEmail := now.Format(time.RFC1123Z)
	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Reply to Reply
Message-ID: <reply2>
In-Reply-To: <reply1>
Content-Type: text/plain

`, dateCEmail), now)

	// 4. Poll again.
	t.Logf("second poll")
	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	msg3 := <-output
	parsed3 := msg3.Email
	assert.Equal(t, "<reply2>", parsed3.MessageID)
	assert.Equal(t, "<root>", msg3.RootMessageID)

	// 5. Save a message from own email.
	t.Logf("saving own email message")
	dateDEmail := now.Add(1 * time.Minute).Format(time.RFC1123Z)
	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: bot@syzbot.com
Date: %s
Subject: Message from Bot
Message-ID: <own-email-msg>
In-Reply-To: <reply2>
Content-Type: text/plain

`, dateDEmail), now.Add(1*time.Minute))

	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	msg4 := <-output
	assert.True(t, msg4.Email.OwnEmail)
}

func TestPollerLoop(t *testing.T) {
	repoDir := t.TempDir()
	loreArchive := NewTestLoreArchive(t, repoDir)

	now := time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC)
	dateStr := now.Format(time.RFC1123Z)

	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Loop 1
Message-ID: <loop1>
In-Reply-To: <loop2>
Content-Type: text/plain

`, dateStr), now)

	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Loop 2
Message-ID: <loop2>
In-Reply-To: <loop1>
Content-Type: text/plain

`, dateStr), now)

	output := make(chan *PolledEmail, 16)
	cfg := PollerConfig{
		RepoDir: t.TempDir(),
		URL:     loreArchive.Repo.Dir,
		now:     func() time.Time { return now },
	}

	poller, err := NewPoller(cfg)
	assert.NoError(t, err)

	ctx := context.Background()
	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	select {
	case msg := <-output:
		t.Errorf("unexpected message in channel: %s", msg.Email.MessageID)
	default:
	}
}

func TestPollerDateSanitization(t *testing.T) {
	repoDir := t.TempDir()
	loreArchive := NewTestLoreArchive(t, repoDir)

	output := make(chan *PolledEmail, 16)
	now := time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC)
	cfg := PollerConfig{
		RepoDir:   t.TempDir(),
		URL:       loreArchive.Repo.Dir,
		OwnEmails: []string{"bot@syzbot.com"},
		now:       func() time.Time { return now },
	}

	poller, err := NewPoller(cfg)
	assert.NoError(t, err)

	ctx := context.Background()

	commitDate := now.Add(-1 * time.Hour)
	loreArchive.SaveMessageAt(t, fmt.Sprintf(`From: someone@domain.com
Date: %s
Subject: Future Dated Message
Message-ID: <future>
Content-Type: text/plain

`, now.Format(time.RFC1123Z)), commitDate)

	err = poller.Poll(ctx, output)
	assert.NoError(t, err)

	msg := <-output
	assert.Equal(t, "<future>", msg.Email.MessageID)
	// The date should be set to commitDate.
	assert.Equal(t, commitDate.UTC(), msg.Email.Date.UTC())
}
