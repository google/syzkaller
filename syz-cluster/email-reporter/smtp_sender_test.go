// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawEmail(t *testing.T) {
	tests := []struct {
		item   *EmailToSend
		id     string
		result string
	}{
		{
			item: &EmailToSend{
				To:        []string{"1@to.com", "2@to.com"},
				Cc:        []string{"1@cc.com", "2@cc.com"},
				InReplyTo: "<reply-to@domain>",
				Subject:   "subject",
				Body:      []byte("Email body"),
			},
			id: "<id@domain>",
			result: "From: name <a@b.com>\r\n" +
				"To: 1@to.com, 2@to.com\r\n" +
				"Cc: 1@cc.com, 2@cc.com\r\n" +
				"Subject: subject\r\n" +
				"In-Reply-To: <reply-to@domain>\r\n" +
				"Message-ID: <id@domain>\r\n" +
				"MIME-Version: 1.0\r\n" +
				"Content-Type: text/plain; charset=UTF-8\r\n" +
				"Content-Transfer-Encoding: 8bit\r\n\r\n" +
				"Email body",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ret := rawEmail(testEmailConfig, test.item, test.id)
			assert.Equal(t, test.result, string(ret))
		})
	}
}
