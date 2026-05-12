// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
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
	require.Empty(t, result.ReportedBy)
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
				},
				RemoveTags: []ai.EmailTag{
					{Tag: "Acked-by", Value: "Drop <drop@email.com>"},
				},
			},
			wantErr: "",
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
					{Tag: "Suggested-by", Value: "Valid <valid@email.com>"},
				},
			},
			wantErr: "tag \"Suggested-by\" is not one of the accepted tags",
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

func TestNormalizeTagValue(t *testing.T) {
	tests := []struct {
		val  string
		want string
	}{
		{"Valid Name <valid@email.com>", "Valid Name <valid@email.com>"},
		{"\"Valid Name\" <valid@email.com>", "Valid Name <valid@email.com>"},
		{"  Valid Name   <valid@email.com>  ", "Valid Name <valid@email.com>"},
		{"valid@email.com", "valid@email.com"},
		{"<valid@email.com>", "valid@email.com"},
		{"not an email", "not an email"}, // Fallback to raw value if it fails to parse.
	}

	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			got := normalizeTagValue(tt.val)
			require.Equal(t, tt.want, got)
		})
	}
}
