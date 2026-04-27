// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// ai package contains common definitions that are used across pkg/aflow/... and dashboard/{app,dashapi}.
package ai

type WorkflowType string

// Note: don't change string values of these types w/o a good reason.
// They are stored in the dashboard database as strings.
const (
	WorkflowPatching           = WorkflowType("patching")
	WorkflowModeration         = WorkflowType("moderation")
	WorkflowAssessmentKCSAN    = WorkflowType("assessment-kcsan")
	WorkflowAssessmentSecurity = WorkflowType("assessment-security")
	WorkflowRepro              = WorkflowType("repro")
	WorkflowReproC             = WorkflowType("repro-c")
)

// Outputs of various workflow types.
// Should be changed carefully since old outputs are stored in the dashboard database.

type PatchingOutputs struct {
	// Base repo/commit for the patch.
	KernelRepo       string
	KernelBranch     string
	KernelCommit     string
	PatchDescription string
	PatchDiff        string
	Recipients       []Recipient
}

type Recipient struct {
	Name  string
	Email string
	To    bool // whether the recipient should be on the To or Cc line
}

type AssessmentKCSANOutputs struct {
	Confident   bool
	Benign      bool
	Explanation string
}

// Note: this struct is used in dashboard config predicates.
// Adding new fields is OK, but deleting/renaming fields is likely to require special care
// (add new fields, update configs, remove old fields).
type AssessmentSecurityOutputs struct {
	Explanation       string
	Exploitable       bool
	DenialOfService   bool
	Unprivileged      bool
	UserNamespace     bool
	VMGuestTrigger    bool
	VMHostTrigger     bool
	NetworkTrigger    bool
	RemoteTrigger     bool
	PeripheralTrigger bool
	FilesystemTrigger bool
}

type ModerationOutputs struct {
	Confident   bool
	Actionable  bool
	Explanation string
}

type ReproOutputs struct {
	ReproSyz              string
	ReproOpts             string
	SyzkallerCommit       string
	Reproduced            bool
	ReproducedCrashReport string
}

type ReproCOutputs struct {
	ReproC                string
	Reproduced            bool
	ReproducedBugTitle    string
	ReproducedCrashReport string
}
