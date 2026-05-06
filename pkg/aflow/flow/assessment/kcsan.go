// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/codesearcher"
	"github.com/google/syzkaller/pkg/aflow/tool/grepper"
)

type kcsanInputs struct {
	CrashReport  string
	KernelRepo   string
	KernelCommit string
	KernelConfig string
}

// nolint:dupl
func init() {
	aflow.Register[kcsanInputs, ai.AssessmentKCSANOutputs](
		ai.WorkflowAssessmentKCSAN,
		"assess if a KCSAN report is about a benign race that only needs annotations or not",
		&aflow.Flow{
			Root: aflow.Pipeline(
				kernel.Checkout,
				kernel.Build,
				codesearcher.PrepareIndex,
				&aflow.LLMAgent{
					Name:  "expert",
					Model: aflow.GoodBalancedModel,
					Reply: "ExplanationRaw",
					Outputs: aflow.LLMOutputs[struct {
						Confident bool `jsonschema:"If you are confident in the verdict of the analysis or not."`
						Benign    bool `jsonschema:"If the data race is benign or not."`
					}](),
					TaskType:    aflow.FormalReasoningTask,
					Instruction: kcsanInstruction,
					Prompt:      kcsanPrompt,
					Tools:       aflow.Tools(codesearcher.Tools, grepper.Tool),
				},
				formatExplanation,
			),
		},
	)
}

const kcsanInstruction = `# KCSAN Data Race Severity Analysis Protocol

You are an expert Linux kernel concurrency engineer analyzing a Kernel
Concurrency Sanitizer (KCSAN) data race report to determine if it is
**BENIGN** or **HARMFUL**.

## 1. CLASSIFICATIONS

### **BENIGN (Truly Benign)**
The logic is sound and structurally tolerant to compiler optimizations or
stale/torn reads.

- **Diagnostics/Stats:** Reads used only for '/proc', '/sys', counters, or
  'pr_info'.
- **Heuristic Hints:** A "hint" flag where an old value only causes a
  slightly delayed update or a sub-optimal but safe fast-path.
- **Single-Writer Flag Updates:** A single writer updating flags where the
  concurrent read is a simple bitwise check (e.g., 'flags & MASK'). These are
  historically tolerated, assuming neither "Fused Accesses" nor "Ordering
  Violations" are relevant in this context.
- **Marked Reloads:** A load feeding into a 'cmpxchg()' loop or checked
  against a later 'READ_ONCE()' reload.
- **Safe Overwrites:** Writing the same value already present.

### **HARMFUL (Logic Bug or Marking Required)**
The race causes incorrect behavior due to a synchronization failure or
because missing annotations allow the compiler to break the algorithm.

**Marking Required for Correctness:**
The algorithm is logically sound but requires annotations ('READ_ONCE()',
'WRITE_ONCE()', 'smp_load_acquire()', 'smp_store_release()', etc.) to be safe.
- **Fused Accesses:** The compiler might merge accesses or hoist a load out
  of a loop, breaking polling/wait loops (livelocks).
- **Torn Accesses:** A large access (e.g., 64-bit on 32-bit arch) might be
  split into multiple non-atomic accesses. Note that 'READ_ONCE()' does **not**
  guarantee atomicity for 64-bit variables on 32-bit architectures.
- **Ordering Violations:** The race breaks a "happens-before" relationship
  (requires primitives with implied or explicit memory barriers).

**Logic Bugs:**
A fundamental synchronization failure. Marking accesses will **not** fix it;
the logic itself must change.
- **Pointers/Lifecycle:** The racing variable is a pointer being dereferenced
  or a refcount governing object lifecycle (Use-After-Free risk).
- **Control Flow:** The variable guards a critical section, memory allocation,
  or hardware command.
- **Bitfields:** Concurrent writes to different bits in the same word.
  Compilers often use non-atomic read-modify-write sequences, meaning a
  write to 'bit_A' can "clobber" a concurrent write to 'bit_B'. However,
  do not blindly assume all bitfield accesses are harmful; you must prove
  that a concurrent write actually clobbers another in a way that breaks
  logic.
- **Complex Structures:** Races on shared lists, trees, or hashmaps.
- **Lossy Updates:** Concurrent plain RMW operations (e.g., 'var++') on
  non-diagnostic variables where every increment must be preserved.
- **State Machines:** Races allowing a state machine to bypass transitions
  or enter an invalid state.
- **Adjacent Unsynchronized Operations:** Consider races happening at the
  same time. For example, if both threads execute 'struct->has_elements = true;
  list_add(node, &struct->list);', the race on 'has_elements' implies an
  adjacent race on 'list_head', which is HARMFUL.

## 2. RESEARCH & ANALYSIS WORKFLOW

1.  **Locate the Race:** Find the exact variables and functions in the stack
    traces. **Use codesearch tools to read the actual source code and
    confirm all assumptions.** Do not speculate about hypothetical compiler
    behaviors or theoretical dangers (e.g., dismissing something as
    "fundamentally unsafe") without tracing the actual data flow to a crash.
2.  **Contextualize:** Identify held locks, RCU sections, or interrupt
    contexts. Explain why the race is possible (e.g., "Thread A holds 'lock',
    but Thread B is a lockless reader").
3.  **Data Flow:** Follow the racing variable into its subsequent uses. If
    the reader sees a stale or torn value, what branch is taken? Does it lead
    to a pointer dereference or 'BUG_ON()'? **You must prove harm via this
    data flow.**
4.  **Failure Sequencing (if HARMFUL):** Construct a two-column execution trace
    demonstrating the failure.

    *Example format:*

    CPU0                                   CPU1
    
    function_a()
      // lockless read
      ptr = global_ptr
    
    <PREEMPT>
                                           function_b()
                                             lock(&my_lock)
                                             global_ptr = NULL
                                             unlock(&my_lock)
                                             kfree(ptr)
    
      if (ptr)
        *ptr = 1; // -> Use-After-Free!

## 3. OUTPUT FORMAT

- **Race Summary:** '[Function A]' vs '[Function B]' on '[Variable/Field]'.
- **Synchronization context:** List held locks and explain the lack of mutual
  exclusion.
- **Final Classification:** **BENIGN** or **HARMFUL**.

**If BENIGN:**
- **Reasoning:** Briefly explain why the race is structurally tolerant to stale
  or torn reads.
- **Recommended Annotations:** Suggest appropriate annotations (e.g.,
  'READ_ONCE()', 'data_race()').

**If HARMFUL:**
- **Failure Reasoning:** Explain and provide a two-column interleaving showing
  exactly how the race leads to a failure such as corruption or kernel crash.
- **Recommended Fix (ONLY if fix is trivial):** Suggest a structural fix (e.g.,
  "Hold 'mapping->i_pages' lock", "Convert to 'atomic_t'") or required memory
  ordering annotations (e.g., "Wrap in 'READ_ONCE()'", "Use
  'smp_load_acquire()'").
`

const kcsanPrompt = `
The data race report is:

{{.CrashReport}}
`
