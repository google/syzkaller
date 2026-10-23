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

var testComments = []ai.ExternalComment{{ExtID: "<c1>"}, {ExtID: "<c2>"}}

func TestMergeTags(t *testing.T) {
	ctx := &aflow.Context{}

	args := tagsMergerArgs{
		NewComments:    testComments,
		BaseReviewedBy: []string{"Old Reviewer <old@rev.com>", "Drop Me <drop@me.com>"},
		BaseTestedBy:   []string{"Existing Tester <test@test.com>"},
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
			// Provided and retracted in the same batch of comments.
			{CommentID: "<c1>", Tag: "Tested-by", Value: "Retracted <retracted@test.com>"},
		},
		RemoveTags: []tagRequest{
			// The value is matched by email.
			{CommentID: "<c2>", Tag: "Reviewed-by", Value: "drop@me.com"},
			{CommentID: "<c2>", Tag: "Tested-by", Value: "retracted@test.com"},
		},
		AddCc:          []ccRequest{{CommentID: "<c1>", Email: "Stable <stable@vger.kernel.org>"}},
		RemoveCc:       []ccRequest{{CommentID: "<c2>", Email: "m1@kernel.org"}},
		BaseRecipients: []ai.Recipient{{Email: "m1@kernel.org", To: true}},
	}

	result, err := mergeTags(ctx, args)
	require.NoError(t, err)

	assert.Equal(t, []string{"Old Reviewer <old@rev.com>", "New Reviewer <new@rev.com>"}, result.ReviewedBy)
	assert.Equal(t, []string{"New Acker <ack@ack.com>"}, result.AckedBy)
	assert.Equal(t, []string{"Existing Tester <test@test.com>"}, result.TestedBy)
	assert.Equal(t, []string{"Suggester <suggester@syzbot.org>"}, result.SuggestedBy)
	assert.Equal(t, []string{"syzbot+12345@testapp.appspotmail.com"}, result.ReportedBy)
	assert.Equal(t, []string{"stable@vger.kernel.org"}, result.AddedCc)
	assert.Equal(t, []string{"m1@kernel.org"}, result.RemovedCc)
	assert.Equal(t, map[string]string{
		"<c1>": `- "add Reviewed-by: New Reviewer <new@rev.com>": applied
- "add Acked-by: New Acker <ack@ack.com>": applied
- "add Tested-by: Existing Tester <test@test.com>": applied
- "add Tested-by: Tester <test@test.com>": applied
- "add Reviewed-by: Old <old@rev.com>": applied
- "add Suggested-by: Suggester <suggester@syzbot.org>": applied
- "add Reported-by: syzbot+12345@testapp.appspotmail.com": applied
- "add Tested-by: Retracted <retracted@test.com>": applied
- "add Stable <stable@vger.kernel.org> to Cc": applied
`,
		"<c2>": `- "remove Reviewed-by: drop@me.com": applied
- "remove Tested-by: retracted@test.com": applied
- "remove m1@kernel.org from To/Cc": applied
`,
	}, result.RequestOutcomes)
}

func TestMergeTagsRejected(t *testing.T) {
	ctx := &aflow.Context{}

	args := tagsMergerArgs{
		NewComments: testComments,
		BaseAckedBy: []string{"Acker <ack@ack.com>"},
		AddTags: []tagRequest{
			{CommentID: "<c1>", Tag: "Foo-by", Value: "Valid <valid@email.com>"},
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "John Smith"},
			{CommentID: "<c1>", Tag: "Reviewed-by", Value: "john@smith.com"},
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
	assert.Equal(t, map[string]string{
		"<c1>": `- "add Foo-by: Valid <valid@email.com>": NOT applied: ` + unsupportedTagReason + `
- "add Reviewed-by: John Smith": NOT applied: ` + invalidTagValueReason + `
- "add Reviewed-by: john@smith.com": NOT applied: ` + invalidTagValueReason + `
`,
		"<c2>": `- "remove Bar-by: Valid <valid@email.com>": NOT applied: ` + unsupportedTagReason + `
- "remove Acked-by: Other <other@ack.com>": NOT applied: ` + missingTagReason + `
- "remove Acked-by: Acker": NOT applied: ` + invalidEmailReason + `
`,
	}, result.RequestOutcomes)
}

func TestMergeTagsCommentOrder(t *testing.T) {
	// The tag is retracted in the first comment and provided again in the later one.
	result, err := mergeTags(&aflow.Context{}, tagsMergerArgs{
		NewComments: testComments,
		BaseAckedBy: []string{"Acker <ack@ack.com>"},
		AddTags:     []tagRequest{{CommentID: "<c2>", Tag: "Acked-by", Value: "Acker <ack@ack.com>"}},
		RemoveTags:  []tagRequest{{CommentID: "<c1>", Tag: "Acked-by", Value: "ack@ack.com"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Acker <ack@ack.com>"}, result.AckedBy)
}

func TestMergeCc(t *testing.T) {
	base := []ai.Recipient{
		{Name: "Maintainer One", Email: "m1@kernel.org", To: true},
		{Name: "Maintainer Two", Email: "m2@kernel.org"},
		{Email: "list@vger.kernel.org"},
	}
	tests := []struct {
		name        string
		addCc       []ccRequest
		removeCc    []ccRequest
		wantAdded   []string
		wantRemoved []string
		wantResults []requestResult
	}{
		{
			name: "no changes",
		},
		{
			name:     "add and remove",
			addCc:    []ccRequest{{"<c1>", "New Name <new@kernel.org>"}},
			removeCc: []ccRequest{{"<c2>", "Maintainer <M2@kernel.org>"}},
			// Addresses are compared case-insensitively.
			wantAdded:   []string{"new@kernel.org"},
			wantRemoved: []string{"m2@kernel.org"},
			wantResults: []requestResult{
				{"<c1>", "add New Name <new@kernel.org> to Cc", ""},
				{"<c2>", "remove Maintainer <M2@kernel.org> from To/Cc", ""},
			},
		},
		{
			name:  "add existing recipient",
			addCc: []ccRequest{{"<c1>", "m1@kernel.org"}},
			wantResults: []requestResult{
				{"<c1>", "add m1@kernel.org to Cc", ""},
			},
		},
		{
			name:  "added and removed in the same batch",
			addCc: []ccRequest{{"<c1>", "new@kernel.org"}},
			removeCc: []ccRequest{
				{"<c2>", "new@kernel.org"},
				{"<c2>", "list@vger.kernel.org"},
			},
			wantRemoved: []string{"list@vger.kernel.org"},
			wantResults: []requestResult{
				{"<c1>", "add new@kernel.org to Cc", ""},
				{"<c2>", "remove new@kernel.org from To/Cc", ""},
				{"<c2>", "remove list@vger.kernel.org from To/Cc", ""},
			},
		},
		{
			name:     "removed and added back in a later comment",
			removeCc: []ccRequest{{"<c1>", "m2@kernel.org"}},
			addCc:    []ccRequest{{"<c2>", "m2@kernel.org"}},
			wantResults: []requestResult{
				{"<c1>", "remove m2@kernel.org from To/Cc", ""},
				{"<c2>", "add m2@kernel.org to Cc", ""},
			},
		},
		{
			name:  "rejected",
			addCc: []ccRequest{{"<c1>", "John Smith"}},
			removeCc: []ccRequest{
				{"<c2>", "missing@kernel.org"},
				{"<c2>", "Maintainer One"},
			},
			wantResults: []requestResult{
				{"<c1>", "add John Smith to Cc", invalidEmailReason},
				{"<c2>", "remove missing@kernel.org from To/Cc", missingAddressReason},
				{"<c2>", "remove Maintainer One from To/Cc", invalidEmailReason},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed, results := mergeCc(base, testComments, tt.addCc, tt.removeCc)
			// ElementsMatch treats nil and empty slices as equal.
			assert.ElementsMatch(t, tt.wantAdded, added)
			assert.ElementsMatch(t, tt.wantRemoved, removed)
			assert.Equal(t, tt.wantResults, results)
		})
	}
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
			// Only comment IDs are validated here, tags and addresses are checked later by mergeTags.
			name: "Unsupported tags and invalid addresses are accepted",
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
			name:    "Missing comment in RemoveTags",
			args:    tagExtractorArgs{RemoveTags: []tagRequest{{Tag: "Acked-by", Value: "a@b.org"}}},
			wantErr: `CommentID "" is not the ExtID of a new comment`,
		},
		{
			name:    "Unknown comment in AddCc",
			args:    tagExtractorArgs{AddCc: []ccRequest{{CommentID: "<c3>", Email: "a@b.org"}}},
			wantErr: `CommentID "<c3>" is not the ExtID of a new comment`,
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
