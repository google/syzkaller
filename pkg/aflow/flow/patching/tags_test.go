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
		BaseRecipients: []ai.Recipient{{Email: "m1@kernel.org", To: true}},
		AddTags: []tagRequest{
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "New Reviewer <new@rev.com>"},
			// Tag names are matched case-insensitively.
			{CommentID: "<c1>", Tag: "acked-BY:", Value: "New Acker <ack@ack.com>"},
			// Duplicate tag to check deduplication.
			{CommentID: "<c1>", Tag: "Tested-by", Value: "Existing Tester <test@test.com>"},
			// Duplicate tag with different name to check email-based deduplication.
			{CommentID: "<c1>", Tag: "Tested-by", Value: "Tester <test@test.com>"},
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "Old <old@rev.com>"},
			{CommentID: "<c1>", Tag: "Suggested-by", Value: "Suggester <suggester@syzbot.org>"},
			// Bots may be referred to by email only.
			{CommentID: "<c1>", Tag: "Reported-by", Value: "syzbot+12345@testapp.appspotmail.com"},
			// Cc/To tags change the recipients.
			{CommentID: "<c1>", Tag: "Cc", Value: "Stable <stable@vger.kernel.org>"},
			// Provided and retracted in the same batch of comments.
			{CommentID: "<c1>", Tag: "Tested-by", Value: "Retracted <retracted@test.com>"},
		},
		RemoveTags: []tagRequest{
			// The value is matched by email.
			{CommentID: "<c2>", Tag: "Reviewed-by", Value: "drop@me.com"},
			{CommentID: "<c2>", Tag: "Tested-by", Value: "retracted@test.com"},
			{CommentID: "<c2>", Tag: "To", Value: "m1@kernel.org"},
		},
	}

	result, err := mergeTags(ctx, args)
	require.NoError(t, err)

	assert.Equal(t, []string{"Old Reviewer <old@rev.com>", "New Reviewer <new@rev.com>"}, result.ReviewedBy)
	assert.Equal(t, []string{"New Acker <ack@ack.com>"}, result.AckedBy)
	assert.Equal(t, []string{"Existing Tester <test@test.com>"}, result.TestedBy)
	assert.Equal(t, []string{"Suggester <suggester@syzbot.org>"}, result.SuggestedBy)
	assert.Equal(t, []string{"syzbot+12345@testapp.appspotmail.com"}, result.ReportedBy)
	assert.Equal(t, []ai.Recipient{{Name: "Stable", Email: "stable@vger.kernel.org"}}, result.Recipients)
	assert.Empty(t, result.RejectedRequests)
}

func TestMergeTagsRejected(t *testing.T) {
	ctx := &aflow.Context{}

	args := tagsMergerArgs{
		BaseAckedBy: []string{"Acker <ack@ack.com>"},
		AddTags: []tagRequest{
			{CommentID: "<c1>", Tag: "Foo-by", Value: "Valid <valid@email.com>"},
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "John Smith"},
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "john@smith.com"},
			{CommentID: "<c1>", Tag: "Cc", Value: "John Smith"},
		},
		RemoveTags: []tagRequest{
			{CommentID: "<c2>", Tag: "Bar-by", Value: "Valid <valid@email.com>"},
			{CommentID: "<c2>", Tag: "Acked-by", Value: "Other <other@ack.com>"},
			{CommentID: "<c2>", Tag: "Acked-by", Value: "Acker"},
		},
	}

	result, err := mergeTags(ctx, args)
	require.NoError(t, err)

	assert.Empty(t, result.ReviewedBy)
	assert.Equal(t, []string{"Acker <ack@ack.com>"}, result.AckedBy)
	assert.Empty(t, result.Recipients)
	assert.Equal(t, []rejectedRequest{
		{"<c1>", "add Foo-by: Valid <valid@email.com>", unsupportedTagReason},
		{"<c1>", "add Reviewed-by: John Smith", invalidTagValueReason},
		{"<c1>", "add Reviewed-by: john@smith.com", invalidTagValueReason},
		{"<c2>", "remove Bar-by: Valid <valid@email.com>", unsupportedTagReason},
		{"<c2>", "remove Acked-by: Other <other@ack.com>", missingTagReason},
		{"<c2>", "remove Acked-by: Acker", invalidEmailReason},
		{"<c1>", "add John Smith to To/Cc", invalidEmailReason},
	}, result.RejectedRequests)
}

func TestMergeRecipients(t *testing.T) {
	m1 := ai.Recipient{Name: "Maintainer One", Email: "m1@kernel.org", To: true}
	m2 := ai.Recipient{Name: "Maintainer Two", Email: "m2@kernel.org"}
	list := ai.Recipient{Email: "list@vger.kernel.org"}
	tests := []struct {
		name         string
		args         tagsMergerArgs
		want         []ai.Recipient
		wantRejected []rejectedRequest
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
				RemoveCc:       []ccRequest{{CommentID: "<c1>", Email: "Maintainer <M2@kernel.org>"}},
				AddCc: []ccRequest{
					{CommentID: "<c1>", Email: "New Name <new@kernel.org>"},
					{CommentID: "<c1>", Email: "m1@kernel.org"},
				},
			},
			want: []ai.Recipient{m1, {Name: "New Name", Email: "new@kernel.org"}},
		},
		{
			name: "added and removed in the same batch",
			args: tagsMergerArgs{
				BaseRecipients: []ai.Recipient{m1},
				NewMaintainers: []ai.Recipient{list},
				AddCc:          []ccRequest{{CommentID: "<c1>", Email: "new@kernel.org"}},
				RemoveCc: []ccRequest{
					{CommentID: "<c2>", Email: "new@kernel.org"},
					{CommentID: "<c2>", Email: "list@vger.kernel.org"},
				},
			},
			want: []ai.Recipient{m1},
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
		{
			name: "rejected",
			args: tagsMergerArgs{
				BaseRecipients: []ai.Recipient{m1},
				RemoveCc: []ccRequest{
					{CommentID: "<c1>", Email: "missing@kernel.org"},
					{CommentID: "<c1>", Email: "Maintainer One"},
				},
				AddCc: []ccRequest{{CommentID: "<c2>", Email: "John Smith"}},
			},
			want: []ai.Recipient{m1},
			wantRejected: []rejectedRequest{
				{"<c2>", "add John Smith to To/Cc", invalidEmailReason},
				{"<c1>", "remove missing@kernel.org from To/Cc", missingAddressReason},
				{"<c1>", "remove Maintainer One from To/Cc", invalidEmailReason},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rejected := mergeRecipients(tt.args)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantRejected, rejected)
		})
	}
}

func TestCommentProcessPrompt(t *testing.T) {
	rejected := []rejectedRequest{
		{"<c1>", "add Foo-by: X <x@y.org>", "unsupported"},
		{"<c2>", "add John to To/Cc", "no email"},
		{"<c1>", "remove a@b.org from To/Cc", "not a recipient"},
	}
	prompt := aflow.TestFormatTemplate(t, commentProcessPrompt, map[string]any{
		"ReproducedBugTitle": "title",
		"CurrentComment":     ai.ExternalComment{ExtID: "<c1>"},
		"RejectedRequests":   rejected,
	})
	assert.Contains(t, prompt, "- \"add Foo-by: X <x@y.org>\": unsupported\n"+
		"- \"remove a@b.org from To/Cc\": not a recipient\n")
	assert.NotContains(t, prompt, "John")
}

func TestValidateTagExtractorOutputs(t *testing.T) {
	ctx := &aflow.Context{}
	state := tagExtractorState{NewComments: []ai.ExternalComment{{ExtID: "<c1>"}, {ExtID: "<c2>"}}}

	tests := []struct {
		name    string
		args    tagExtractorArgs
		wantErr string
	}{
		{
			name: "Valid",
			args: tagExtractorArgs{
				AddTags:    []tagRequest{{CommentID: "<c1>", Tag: "Foo-by", Value: "John Smith"}},
				RemoveTags: []tagRequest{{CommentID: "<c2>", Tag: "Acked-by", Value: "a@b.org"}},
				AddCc:      []ccRequest{{CommentID: "<c1>", Email: "John Smith"}},
				RemoveCc:   []ccRequest{{CommentID: "<c2>", Email: "a@b.org"}},
			},
		},
		{
			name:    "Unknown comment in AddTags",
			args:    tagExtractorArgs{AddTags: []tagRequest{{CommentID: "<c3>", Tag: "Acked-by", Value: "a@b.org"}}},
			wantErr: `CommentID "<c3>" is not the ExtID of a new comment`,
		},
		{
			name:    "Unknown comment in RemoveCc",
			args:    tagExtractorArgs{RemoveCc: []ccRequest{{Email: "a@b.org"}}},
			wantErr: `CommentID "" is not the ExtID of a new comment`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateTagExtractorOutputs(ctx, state, tt.args)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.args, got)
		})
	}
}
