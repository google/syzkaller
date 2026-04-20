// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
)

// extractCommands converts parsed email commands into Dashboard API requests.
func extractCommands(polled *lore.PolledEmail) []*dashapi.SendExternalCommandReq {
	var reqs []*dashapi.SendExternalCommandReq

	for _, cmd := range polled.Email.Commands {
		req := &dashapi.SendExternalCommandReq{
			Source:       dashapi.AIJobSourceLore,
			RootExtID:    polled.RootMessageID,
			MessageExtID: polled.Email.MessageID,
			Author:       polled.Email.Author,
		}

		switch cmd.Command {
		case email.CmdUpstream:
			req.Upstream = &dashapi.UpstreamCommand{}
			reqs = append(reqs, req)
		case email.CmdReject:
			req.Reject = &dashapi.RejectCommand{
				Reason: polled.Email.Body,
			}
			reqs = append(reqs, req)
		}
	}

	if len(reqs) == 0 && polled.Email.Body != "" {
		reqs = append(reqs, &dashapi.SendExternalCommandReq{
			Source:       dashapi.AIJobSourceLore,
			RootExtID:    polled.RootMessageID,
			MessageExtID: polled.Email.MessageID,
			Author:       polled.Email.Author,
			Comment: &dashapi.CommentCommand{
				Body: polled.Email.Body,
			},
		})
	}

	return reqs
}
