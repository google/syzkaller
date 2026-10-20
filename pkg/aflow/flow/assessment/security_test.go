// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRootCauseOutputs(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "net", "ipv4"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "net", "ipv4", "tcp_input.c"), []byte("int x;"), 0644))

	state := rootCauseValidationState{KernelSrc: tmpDir}

	got, err := validateRootCauseOutputs(nil, state, rootCauseOutputs{
		RootCauseSummary: "  UAF in tcp_input  ",
		RootCauseFiles:   []string{"/net/ipv4/tcp_input.c", "net/ipv4/tcp_input.c", "net/ipv4/nonexistent.c", "net/ipv4"},
		InfoLeak:         ai.InfoLeakPointers,
	})
	require.NoError(t, err)
	assert.Equal(t, "UAF in tcp_input", got.RootCauseSummary)
	assert.Equal(t, []string{"net/ipv4/tcp_input.c"}, got.RootCauseFiles)

	_, err = validateRootCauseOutputs(nil, state, rootCauseOutputs{
		RootCauseSummary: "summary",
		RootCauseFiles:   []string{"net/ipv4"},
		InfoLeak:         ai.InfoLeakNone,
	})
	require.ErrorContains(t, err, `"net/ipv4" is a directory, expected a file`)

	for _, bad := range []rootCauseOutputs{
		{RootCauseFiles: []string{"net/ipv4/tcp_input.c"}, InfoLeak: ai.InfoLeakNone},
		{RootCauseSummary: "summary", InfoLeak: ai.InfoLeakNone},
		{RootCauseSummary: "summary", RootCauseFiles: []string{"net/ipv4/nonexistent.c"}, InfoLeak: ai.InfoLeakNone},
		{RootCauseSummary: "summary", RootCauseFiles: []string{"."}, InfoLeak: ai.InfoLeakNone},
		{RootCauseSummary: "summary", RootCauseFiles: []string{"../etc/passwd"}, InfoLeak: ai.InfoLeakNone},
		{RootCauseSummary: "summary", RootCauseFiles: []string{"net/ipv4/tcp_input.c"}, InfoLeak: "yes"},
	} {
		_, err := validateRootCauseOutputs(nil, state, bad)
		require.Error(t, err, "%+v", bad)
	}
}

func TestValidateReachabilityOutputs(t *testing.T) {
	got, err := validateLocalReachabilityOutputs(nil, struct{}{}, localReachabilityOutputs{
		UserNamespace: true,
		RequiredCaps:  []string{"CAP_NET_RAW", " cap_net_admin ", "CAP_NET_ADMIN"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"CAP_NET_ADMIN", "CAP_NET_RAW"}, got.RequiredCaps)

	for _, bad := range []localReachabilityOutputs{
		{Unprivileged: true, UserNamespace: false},
		{Unprivileged: true, UserNamespace: true, RequiredCaps: []string{"CAP_NET_ADMIN"}},
		{RequiredCaps: []string{"CAP_FOOBAR"}},
		{Unprivileged: true, UserNamespace: true, RawFuzzingArtifact: true},
	} {
		_, err := validateLocalReachabilityOutputs(nil, struct{}{}, bad)
		require.Error(t, err, "%+v", bad)
	}

	_, err = validateNetReachabilityOutputs(nil, struct{}{}, netReachabilityOutputs{
		NetworkNeedsSetup: true,
	})
	require.Error(t, err)
}

func TestCombineAssessment(t *testing.T) {
	res, err := combineAssessmentFunc(nil, combineAssessmentArgs{
		RootCauseAnalysis:         "UAF in foo.",
		LocalReachabilityAnalysis: "Reachable via userns CAP_NET_ADMIN.",
		NetReachabilityAnalysis:   "Also reachable via ingress TCP packets.",
		MemoryCorruption:          true,
		InfoLeak:                  ai.InfoLeakNone,
		RawDenialOfService:        true,
		NetworkTrigger:            true,
	})
	require.NoError(t, err)
	assert.True(t, res.Exploitable)
	assert.True(t, res.DenialOfService)
	assert.False(t, res.FuzzingArtifact)
	assert.Contains(t, res.Explanation, "Root Cause Analysis:\n\nUAF in foo.")
	assert.Contains(t, res.Explanation, "Network Reachability Analysis:\n\nAlso reachable via ingress TCP")
	assert.NotContains(t, res.Explanation, "Virtualization Reachability Analysis:")

	// Pointer leak alone is exploitable.
	res, err = combineAssessmentFunc(nil, combineAssessmentArgs{
		InfoLeak: ai.InfoLeakPointers,
	})
	require.NoError(t, err)
	assert.True(t, res.Exploitable)

	// Fuzzing artifact clears Exploitable and DenialOfService unless an external trigger is set.
	res, err = combineAssessmentFunc(nil, combineAssessmentArgs{
		MemoryCorruption:   true,
		InfoLeak:           ai.InfoLeakNone,
		RawDenialOfService: true,
		RawFuzzingArtifact: true,
	})
	require.NoError(t, err)
	assert.False(t, res.Exploitable)
	assert.False(t, res.DenialOfService)
	assert.True(t, res.FuzzingArtifact)

	res, err = combineAssessmentFunc(nil, combineAssessmentArgs{
		InfoLeak:           ai.InfoLeakNone,
		RawDenialOfService: true,
		RawFuzzingArtifact: true,
		NetworkTrigger:     true,
	})
	require.NoError(t, err)
	assert.False(t, res.Exploitable)
	assert.True(t, res.DenialOfService)
	assert.False(t, res.FuzzingArtifact)
}
