// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/stretchr/testify/assert"
)

func TestMapCommands(t *testing.T) {
	tests := []struct {
		name   string
		polled *lore.PolledEmail
		want   []*dashapi.SendExternalCommandReq
	}{
		{
			name: "upstream",
			polled: &lore.PolledEmail{
				RootMessageID: "<root@id>",
				Email: &lore.Email{
					Email: &email.Email{
						MessageID: "<msg@id>",
						Author:    "user@example.com",
						Commands: []*email.SingleCommand{
							{Command: email.CmdUpstream},
						},
					},
				},
			},
			want: []*dashapi.SendExternalCommandReq{
				{
					Source:       dashapi.AIJobSourceLore,
					RootExtID:    "<root@id>",
					MessageExtID: "<msg@id>",
					Author:       "user@example.com",
					Upstream:     &dashapi.UpstreamCommand{},
				},
			},
		},
		{
			name: "reject",
			polled: &lore.PolledEmail{
				RootMessageID: "<root@id>",
				Email: &lore.Email{
					Email: &email.Email{
						MessageID: "<msg@id>",
						Author:    "user@example.com",
						Body:      "some reason",
						Commands: []*email.SingleCommand{
							{Command: email.CmdReject},
						},
					},
				},
			},
			want: []*dashapi.SendExternalCommandReq{
				{
					Source:       dashapi.AIJobSourceLore,
					RootExtID:    "<root@id>",
					MessageExtID: "<msg@id>",
					Author:       "user@example.com",
					Reject:       &dashapi.RejectCommand{Reason: "some reason"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractCommands(tc.polled)
			assert.Equal(t, tc.want, got)
		})
	}
}
