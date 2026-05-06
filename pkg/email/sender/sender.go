// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sender

import "context"

// Email represents an email to be sent.
type Email struct {
	To        []string
	Cc        []string
	Subject   string
	InReplyTo string
	Body      []byte
	BugID     string
}

// Sender defines the interface for sending emails.
type Sender interface {
	Send(ctx context.Context, email *Email) (string, error)
}
