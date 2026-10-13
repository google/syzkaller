// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeTags(t *testing.T) {
	ctx := &aflow.Context{}

	args := tagsMergerArgs{
		BaseReviewedBy: []string{"Old Reviewer <old@rev.com>", "Drop Me <drop@me.com>"},
		BaseTestedBy:   []string{"Existing Tester <test@test.com>"},
		AddTags: []ai.EmailTag{
			{Tag: "Reviewed-by", Value: "New Reviewer <new@rev.com>"},
			{Tag: "Acked-by", Value: "New Acker <ack@ack.com>"},
			// Duplicate tag to check deduplication.
			{Tag: "Tested-by", Value: "Existing Tester <test@test.com>"},
			// Duplicate tag with different name to check email-based deduplication.
			{Tag: "Tested-by", Value: "test@test.com"},
			{Tag: "Reviewed-by", Value: "old@rev.com"},
			{Tag: "Suggested-by", Value: "Suggester <suggester@syzbot.org>"},
		},
		RemoveTags: []ai.EmailTag{
			{Tag: "Reviewed-by", Value: "Drop Me <drop@me.com>"},
		},
	}

	result, err := mergeTags(ctx, args)
	require.NoError(t, err)

	require.Equal(t, []string{"Old Reviewer <old@rev.com>", "New Reviewer <new@rev.com>"}, result.ReviewedBy)
	require.Equal(t, []string{"New Acker <ack@ack.com>"}, result.AckedBy)
	require.Equal(t, []string{"Existing Tester <test@test.com>"}, result.TestedBy)
	require.Equal(t, []string{"Suggester <suggester@syzbot.org>"}, result.SuggestedBy)
	require.Empty(t, result.ReportedBy)
}

func TestMergeRecipients(t *testing.T) {
	m1 := ai.Recipient{Name: "Maintainer One", Email: "m1@kernel.org", To: true}
	m2 := ai.Recipient{Name: "Maintainer Two", Email: "m2@kernel.org"}
	list := ai.Recipient{Email: "list@vger.kernel.org"}
	tests := []struct {
		name string
		args tagsMergerArgs
		want []ai.Recipient
	}{
		{
			name: "no changes",
			args: tagsMergerArgs{BaseRecipients: []ai.Recipient{m1, m2}},
			want: []ai.Recipient{m1, m2},
		},
		{
			name: "add and remove",
			args: tagsMergerArgs{
				BaseRecipients: []ai.Recipient{m1, m2},
				RemoveCc:       []string{"M2@kernel.org"},
				AddCc:          []string{"new@kernel.org", "m1@kernel.org"},
			},
			want: []ai.Recipient{m1, {Email: "new@kernel.org"}},
		},
		{
			name: "new maintainers",
			args: tagsMergerArgs{
				BaseRecipients: []ai.Recipient{m1},
				NewMaintainers: []ai.Recipient{m1, list},
			},
			want: []ai.Recipient{m1, list},
		},
		{
			name: "no base recipients",
			args: tagsMergerArgs{NewMaintainers: []ai.Recipient{m1, m2}},
			want: []ai.Recipient{m1, m2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mergeRecipients(tt.args))
		})
	}
}

func TestValidateTagExtractorOutputs(t *testing.T) {
	ctx := &aflow.Context{}

	tests := []struct {
		name    string
		state   tagExtractorState
		args    tagExtractorArgs
		want    tagExtractorArgs
		wantErr string
	}{
		{
			name: "Valid tags",
			state: tagExtractorState{
				BaseAckedBy: []string{"Drop <drop@email.com>"},
			},
			args: tagExtractorArgs{
				AddTags: []ai.EmailTag{
					{Tag: "Reviewed-by", Value: "Valid Name <valid@email.com>"},
					{Tag: "Tested-by", Value: "Valid Tester <test@email.com>"},
					{Tag: "Reported-by", Value: "syzbot+12345@testapp.appspotmail.com"},
					{Tag: "Suggested-by", Value: "Suggester <suggester@syzbot.org>"},
				},
				RemoveTags: []ai.EmailTag{
					{Tag: "Acked-by", Value: "Drop <drop@email.com>"},
				},
			},
			want: tagExtractorArgs{
				AddTags: []ai.EmailTag{
					{Tag: "Reviewed-by", Value: "Valid Name <valid@email.com>"},
					{Tag: "Tested-by", Value: "Valid Tester <test@email.com>"},
					{Tag: "Reported-by", Value: "syzbot+12345@testapp.appspotmail.com"},
					{Tag: "Suggested-by", Value: "Suggester <suggester@syzbot.org>"},
				},
				RemoveTags: []ai.EmailTag{
					{Tag: "Acked-by", Value: "Drop <drop@email.com>"},
				},
			},
			wantErr: "",
		},
		{
			name: "Valid Cc",
			state: tagExtractorState{
				BaseRecipients: []ai.Recipient{{Name: "Maintainer", Email: "maint@kernel.org", To: true}},
			},
			args: tagExtractorArgs{
				AddCc:    []string{"Ignored Name <added@kernel.org>", "plain@kernel.org"},
				RemoveCc: []string{"Maintainer <maint@kernel.org>"},
			},
			want: tagExtractorArgs{
				AddCc:    []string{"added@kernel.org", "plain@kernel.org"},
				RemoveCc: []string{"maint@kernel.org"},
			},
		},
		{
			name: "Remove missing tag",
			state: tagExtractorState{
				BaseAckedBy: []string{},
			},
			args: tagExtractorArgs{
				RemoveTags: []ai.EmailTag{
					{Tag: "Acked-by", Value: "Drop <drop@email.com>"},
				},
			},
			wantErr: "tag \"Acked-by\" with value \"Drop <drop@email.com>\" " +
				"is not present in the patch, so it cannot be removed",
		},
		{
			name: "Unsupported tag type",
			args: tagExtractorArgs{
				AddTags: []ai.EmailTag{
					{Tag: "Foo-by", Value: "Valid <valid@email.com>"},
				},
			},
			wantErr: "tag \"Foo-by\" is not one of the accepted tags",
		},
		{
			name: "Invalid email",
			args: tagExtractorArgs{
				AddTags: []ai.EmailTag{
					{Tag: "Reviewed-by", Value: "not an email"},
				},
			},
			wantErr: "value for tag \"Reviewed-by\" must be a valid name and email",
		},
		{
			name:    "Invalid AddCc email",
			args:    tagExtractorArgs{AddCc: []string{"Just A Name"}},
			wantErr: `value "Just A Name" in AddCc must be a valid email address`,
		},
		{
			name:    "Remove missing recipient",
			state:   tagExtractorState{BaseRecipients: []ai.Recipient{{Email: "present@kernel.org"}}},
			args:    tagExtractorArgs{RemoveCc: []string{"missing@kernel.org"}},
			wantErr: `recipient "missing@kernel.org" is not present in the current recipient list`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateTagExtractorOutputs(ctx, tt.state, tt.args)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}
