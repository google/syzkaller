// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/google/syzkaller/pkg/email"
)

// TODO: there's a lot of common code with series-tracker.
// TODO: alternatively, we could parse the whole archive and track each email via In-Reply-To to the original email.

type LoreEmailStreamer struct {
}

func NewLoreEmailStreamer() *LoreEmailStreamer {
	return &LoreEmailStreamer{}
}

func (s *LoreEmailStreamer) Loop(ctx context.Context, writeTo chan *email.Email) {
	<-ctx.Done()

	// !! We assume that the archive mostly consists of relevant emails.
	// 1. Query the last recorded discussion via API.
	// 2. Poll the lore archive and query the emails starting from the date returned in (1).
	// 3. Parse the email using email.Parse().
	// 4. Report the new email via API, figure out which report was involved, save report ID to msg's BugIDs.
	// 5. Push to the channel only if the message has not been seen before.
	//    Also, we probablty don't want to react to old messages (e.g. > 1 day from now).
}
