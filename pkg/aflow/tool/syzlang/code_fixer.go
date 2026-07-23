package syzlang

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

type CodeFixerArgs struct {
	BaseTestSeed                    string `jsonschema:"Base seed path. MUST be provided if requested."`
	SyzProgram                      string `jsonschema:"The syzlang program that needs debugging."`
	AcceptableCallErrorsDescription string `jsonschema:"Allowed call errors (e.g. EINVAL on ioctl)."`
	ProgramIntentDescription        string `jsonschema:"High-level description of program setup intent."`
}

type CodeFixerResult struct {
	ExecutionCachedID string `jsonschema:"Successful execution cached ID. Empty if giving up."`
	CodeFixerGiveUp   bool   `jsonschema:"Set true if program cannot be fixed."`
	CodeFixerReason   string `jsonschema:"Reason for giving up."`
	Program           string `jsonschema:"Leave this empty. It will be replaced automatically."`
	BaseTestSeed      string `jsonschema:"Leave this empty. It will be replaced automatically."`
	ProgramDiff       string `jsonschema:"Leave this empty. It will be replaced automatically."`
}

func validateCodeFixerOutputs(
	ctx *aflow.Context, state struct{}, args CodeFixerArgs, res CodeFixerResult,
) (CodeFixerResult, error) {
	if res.CodeFixerGiveUp {
		res.ExecutionCachedID = ""
		if res.CodeFixerReason == "" {
			return res, aflow.BadCallError("must provide CodeFixerReason if giving up")
		}
		return res, nil
	}
	res.ExecutionCachedID = strings.TrimSpace(res.ExecutionCachedID)
	if res.ExecutionCachedID == "" {
		return res, aflow.BadCallError("returned ExecutionCachedID cannot be empty if not giving up")
	}
	baseSeed, finalProg, err := crash.LoadSeedProgramDetails(ctx, res.ExecutionCachedID)
	if err != nil {
		return res, aflow.BadCallError("invalid ExecutionCachedID %q: %v. "+
			"You must return the ExecutionCachedID of a successful run.", res.ExecutionCachedID, err)
	}
	res.Program = finalProg
	res.BaseTestSeed = baseSeed
	res.ProgramDiff = diffPrograms(args.SyzProgram, finalProg)
	return res, nil
}

var CodeFixer = &aflow.StructuredLLMTool[struct{}, CodeFixerArgs, CodeFixerResult]{
	Name:       "code-fixer",
	Model:      aflow.TemporaryFlashOnlyModel,
	Outputs:    aflow.ValidatedLLMToolOutputs[CodeFixerResult, struct{}, CodeFixerArgs](validateCodeFixerOutputs),
	TaskType:   aflow.FormalReasoningTask,
	PreExecute: ResolveSyzlangDependencies,
	ExtraVars: map[string]reflect.Type{
		"StaticDefinitions": reflect.TypeFor[string](),
	},
	Description: "A subagent tool that takes a syzlang program and repeatedly executes it " +
		"until it has no compilation or unacceptable runtime call errors. " +
		"It can handle expected call errors described by the parent, but will fail/give up on unexpected/unfixable errors.",
	Instruction: `You are an expert syzkaller seed debugger.
The parent Generator has provided an initial syzlang program to reach the target.
You may also be provided with a Base Test Seed path (e.g. test/vusb_cdc_ecm) which sets up the environment.
These test seeds are not for you to understand in detail, but only to set up some environment
like devices or file system.
Your job is ONLY to debug any syntax/compilation or unacceptable call errors in the provided syzlang program.
Do NOT generate new logic to reach something or debug why something is not reached.
This constraint means you must not append entirely new system call sequences or invent driver call flows
that were not in the parent program. However, you are fully allowed to edit or modify arguments,
variable assignments, flag constants, and types to fix syntax/compilation errors or match syzlang specifications.

CRITICAL SEED INTEGRITY CONSTRAINTS:
1. Respect 'ProgramIntentDescription': Do NOT remove, swap, or modify core setup syscalls or target subsystem
   identifiers that would violate the intended setup described in 'ProgramIntentDescription'.
2. Do NOT delete primary setup or target syscalls (e.g., removing 'mkdirat', 'symlinkat', 'syz_usb_connect', or main
   syscalls) simply because they return an unacceptable call error.
3. Do NOT swap target driver/subsystem string identifiers or device types to bypass call errors.
4. If a system call fails with an unacceptable call error (e.g., ENOENT, EINVAL, ENOSYS, EEXIST) that cannot
   be resolved by adjusting arguments to match syzlang specifications or removing duplicate setup calls already
   present in 'BaseTestSeed', you MUST set CodeFixerGiveUp = true immediately and explain the exact failing call
   and error in CodeFixerReason.
5. Deleting failing setup lines or substituting target subsystem types to force a clean execution invalidates
   the program and is strictly forbidden.
You have been provided with an 'AcceptableCallErrorsDescription'.
Any call error returned by '{{.toolExecuteSeed}}' that matches this description
is acceptable/expected and can be ignored.
All other call errors (e.g. EFAULT, EINVAL, or ENOSYS) not matching this description are unacceptable,
and you MUST attempt to fix them.
If the seed executes successfully (i.e. all compilation/syntax errors are resolved, and any remaining
call errors match AcceptableCallErrorsDescription), you MUST immediately yield by returning the
ExecutionCachedID as your final reply. DO NOT call any other tool to double check or verify.
It is NOT your job to reason, verify, or simplify the program.
If you encounter unacceptable call errors (such as ENOSYS/Function not implemented, or unexpected errors)
that cannot be fixed (e.g. due to VM/environment limits) or if execute-seed returns a kernel crash error
("kernel crashed: ..."), you MUST set CodeFixerGiveUp = true (if there is no other way to reach the target location)
and provide a detailed reason in CodeFixerReason.
If execute-seed returns a sandbox escape error ("filename ... escapes sandbox") on a 'symlink', 'symlinkat', or 'openat'
call (e.g. attempting to use '..', '/sys/...', or generic 'openat' on '/dev/...'):
1. For device nodes (e.g. '/dev/kvm', '/dev/fuse'), check if a specialized variant (e.g., 'openat$kvm',
   'openat$fuse') or pseudo-syscall (e.g., 'syz_open_dev$char') exists using '{{.toolSyzGrepper}}' and replace
   generic 'openat' with that variant.
2. For ConfigFS/sysfs, ensure the filesystem is mounted locally (e.g. 'mkdirat(AT_FDCWD, "./config", 0777)'
   then 'mount(0, "./config", "configfs", 0, 0)').
3. Rewrite absolute or '..' paths to CWD-relative paths (e.g., rewrite '../../functions/name' or
   '/sys/kernel/config/...' to './config/usb_gadget/.../functions/name').
Do NOT attempt tricks like './dir/../../path'; filepath.Clean() normalizes them to '../path' which is rejected.
Do NOT give up on sandbox-escape errors for ConfigFS or sysfs; rewrite them using the CWD-relative Local Mount Pattern.
You MUST:
1. Execute the syzlang program using '{{.toolExecuteSeed}}'. (CRITICAL INSTRUCTION) You must pass the
   BaseTestSeed to the tool if one was provided in your prompt. You should prefer keeping it, but you are
   allowed to change, swap, or remove it. If the base test seed itself fails or conflicts with your program,
   you are explicitly allowed and encouraged to clear/remove the base test seed (by setting BaseTestSeed to
   an empty string in the results or omitting it) or swap it for a different seed. Do not assume the
   base seed is an immutable constraint if it causes runtime failures.
   Any errors in the base test seed indicate environment setup issues. If the base seed fails and you
   cannot resolve it, set CodeFixerGiveUp = true and report it.
   * Handling EEXIST / EBUSY: If execution fails with EEXIST ('File exists') or EBUSY ('Device or resource busy'),
     check if the syzlang program duplicates environment setup calls (e.g. 'syz_mount_image', 'syz_usb_connect',
     'mkdirat') already executed in 'BaseTestSeed'. Either remove the redundant setup calls from the syzlang
     program OR clear 'BaseTestSeed' (set to "") so setup calls are not executed twice.
2. If there are syntax errors or unacceptable call errors, fix them using '{{.toolReadSyzSpec}}' and
   '{{.toolSyzGrepper}}' to ensure arguments match expected descriptions.
3. Execute again until you get a successful execution or decide to give up.
4. If successful, provide the ExecutionCachedID as your final text reply. If giving up, set CodeFixerGiveUp = true
   and provide CodeFixerReason.
Do NOT attempt to verify PC coverage, diagnose divergence, or simplify the program.
That will be handled by the pipeline.

` + TestSeedConstraints + "\n\n" + `
` + SyzlangSyntaxConstraints + "\n\n" + `
` + SandboxConstraints + "\n\n" + `
` + PseudoSyscallConstraints + "\n\n" + `
===
{{.DocProgramSyntax}}
===

Document about syzlang system call descriptions syntax:
===
{{.DocSyscallDescriptionsSyntax}}
===

Document about pseudo-syscalls:
===
{{.DocPseudoSyscalls}}
===

Document about SyzOS setup:
===
{{.DocSyzOS}}
===

`,
	Tools: aflow.Tools(
		ExecuteSeed,
		ReadSyzSpec,
		SyzGrepper,
	),
	Judge: &aflow.LLMJudge{
		Name:               "code-fixer-judge",
		Model:              aflow.TemporaryFlashOnlyModel,
		MinIterations:      50,
		EvaluationInterval: 20,
		Instruction: "You are a Judge Agent monitoring the execution of a subagent debugging a syzlang program.\n" +
			"Your job is to look at the history of attempts and decide if the subagent is stuck " +
			"in a loop, oscillating between different errors without progress, or otherwise runaway.\n\n" +
			"Analyze the history:\n" +
			"- Look at the syzlang programs and compilation/runtime execution errors in successive turns.\n" +
			"- Check if the subagent is oscillating (e.g. changing an argument from X to Y, " +
			"getting an error, changing it back to X, getting the previous error).\n" +
			"- Check if the subagent is repeating the exact same error for more than 3 turns " +
			"without any meaningful modification to the code structure.\n" +
			"- Check if it is making zero progress toward successful compilation/execution.\n\n" +
			"Decision Criteria:\n" +
			"- Set Stop = true if there is a clear loop, oscillation, or lack of progress.\n" +
			"- If setting Stop = true, provide a clear, concise and actionable Reason summarizing " +
			"the loop or why progress is blocked. This reason will be returned as an error to " +
			"the parent agent, helping it try a different strategy.\n" +
			"- Set Stop = false if the subagent is introducing new changes, trying new paths, " +
			"or making progress towards resolving the errors.",
	},
	Prompt: `{{if .AcceptableCallErrorsDescription}}Acceptable/Expected Call Errors Description:
{{.AcceptableCallErrorsDescription}}
If any call error matching this description occurs, it is acceptable. Do NOT try to fix it.
All other call errors NOT matching this description are unacceptable, and you MUST fix them or give up.

{{end}}{{if .ProgramIntentDescription}}Generator's Program Intent:
{{.ProgramIntentDescription}}
Do NOT alter, remove, or swap core setup calls or subsystem types that would violate this intent.
If fixing a call error requires violating this intent, set CodeFixerGiveUp = true.

{{end}}{{if .BaseTestSeed}}Base Test Seed: {{.BaseTestSeed}}

{{end}}{{if .StaticDefinitions}}Static definitions of syscalls and types referenced in the program:
===
{{.StaticDefinitions}}===

{{end}}Generator's Syzlang Program:
{{.SyzProgram}}`,
}

func diffPrograms(original, fixed string) string {
	// Ensure both strings end with a newline to avoid diffs on missing EOF.
	original = ensureTrailingNewline(original)
	fixed = ensureTrailingNewline(fixed)
	edits := myers.ComputeEdits(span.URIFromPath("original"), original, fixed)
	return fmt.Sprint(gotextdiff.ToUnified("original", "fixed", original, edits))
}

func ensureTrailingNewline(s string) string {
	if s != "" && !strings.HasSuffix(s, "\n") {
		return s + "\n"
	}
	return s
}
