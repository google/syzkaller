// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "context"

// TODO: how can we test it?
// Using some STMP server library is probably an overkill?

type smtpSender struct {
}

// Send constructs a raw email from EmailToSend and sends it over SMTP.
func (sender *smtpSender) Send(ctx context.Context, item *EmailToSend) (string, error) {
	// TODO:
	// 1) Fill in email headers, including the Message ID.
	// https://pkg.go.dev/github.com/emersion/go-message/mail#Header.GenerateMessageIDWithHostname
	// 2) Send over STMP:
	// https://pkg.go.dev/net/smtp
	return "", nil
}
