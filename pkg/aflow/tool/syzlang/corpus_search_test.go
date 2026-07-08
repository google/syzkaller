// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/stretchr/testify/require"
)

func TestCorpusCodeSearch(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	cData := syzspec.CorpusData{
		Programs: map[string]string{
			"h1": "openat$kvm(0x1, 0x2)",
			"h2": "ioctl$KVM_CREATE_VM(0x3)",
			"h3": "ioctl$KVM_RUN(0x4)\nopenat$kvm(0x5)",
		},
		FunctionMap: map[string][]string{
			"kvm_vcpu_ioctl": {"h2", "h3"},
			"kvm_vm_ioctl":   {"h1"},
		},
		SyscallMap: map[string][]string{
			"openat$kvm":          {"h1", "h3"},
			"ioctl$KVM_CREATE_VM": {"h2"},
			"ioctl$KVM_RUN":       {"h3"},
		},
	}

	_, cachedID, err := aflow.CacheObject(ctx, "corpus-execution", "test-desc", func() (syzspec.CorpusData, error) {
		return cData, nil
	})
	require.NoError(t, err)

	tests := []struct {
		name         string
		functionName string
		syscallName  string
		wantContains []string
		wantError    bool
	}{
		{
			name:         "only function name",
			functionName: "kvm_vcpu_ioctl",
			wantContains: []string{
				"Found 2 corpus programs reaching function \"kvm_vcpu_ioctl\"",
				"ioctl$KVM_CREATE_VM",
				"ioctl$KVM_RUN",
			},
		},
		{
			name:        "only syscall name exact",
			syscallName: "openat$kvm",
			wantContains: []string{
				"Found 2 corpus programs containing syscall matching \"openat$kvm\"",
				"openat$kvm(0x1, 0x2)",
				"ioctl$KVM_RUN(0x4)",
			},
		},
		{
			name:        "only syscall name substring case-insensitive",
			syscallName: "KVM",
			wantContains: []string{
				"Found 3 corpus programs containing syscall matching \"KVM\"",
				"openat$kvm(0x1, 0x2)",
				"ioctl$KVM_CREATE_VM",
				"ioctl$KVM_RUN",
			},
		},
		{
			name:         "both function and syscall (error)",
			functionName: "kvm_vcpu_ioctl",
			syscallName:  "openat$kvm",
			wantError:    true,
		},
		{
			name:      "both empty (error)",
			wantError: true,
		},
		{
			name:         "no matches",
			functionName: "non_existent_function",
			wantContains: []string{
				"No corpus programs found reaching function \"non_existent_function\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := CorpusCodeSearchState{CorpusExecutionCachedID: cachedID}
			args := CorpusCodeSearchArgs{
				FunctionName: tt.functionName,
				SyscallName:  tt.syscallName,
			}
			res, err := corpusCodeSearch(ctx, state, args)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				for _, expected := range tt.wantContains {
					require.Contains(t, res.Output, expected)
				}
			}
		})
	}
}
