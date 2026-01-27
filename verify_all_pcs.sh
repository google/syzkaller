#!/bin/bash
# Verify native symbolizer against llvm-symbolizer for all KCOV PCs
set -e

VMLINUX=${VMLINUX:-$HOME/projects/fuzzing-qemu/linux-stable/vmlinux}
SYZ_SYM_CHECK=./bin/syz-sym-check
LLVM_SYMBOLIZER=$(which llvm-symbolizer)

if [ ! -f "$VMLINUX" ]; then
    echo "Error: vmlinux not found at $VMLINUX"
    exit 1
fi

if [ ! -x "$SYZ_SYM_CHECK" ]; then
    echo "Error: syz-sym-check not found at $SYZ_SYM_CHECK. Run 'go build -o bin/syz-sym-check tools/syz-sym-check/main.go'"
    exit 1
fi

if [ -z "$LLVM_SYMBOLIZER" ]; then
    echo "Error: llvm-symbolizer not found in PATH"
    exit 1
fi

echo "Extracting KCOV PCs from $VMLINUX..."
# Extract addresses of calls to __sanitizer_cov_trace_pc
# nm -n $VMLINUX | grep __sanitizer_cov_trace_pc
# But we need call sites.
# Using objdump is better but slow.
# Alternative: user complained about mismatch, so maybe just random sample?
# User said "reads all the KCOV PCs".
# We can use `objdump -d` and grep for call instructions to trace_pc.
# This might take a while.
# Faster: just check standard text symbols?
# No, KCOV PCs are specific call sites.
# Let's try objdump.

# Only take top 1000 for sanity check first?
# "reads all" implies all.
# But vmlinux is huge.
# Let's do it efficiently.

# We need the address of the instruction *after* the call (return address).
# Or the address of the call? syzkaller uses return addresses usually (PC).
# Wait, KCOV instrumentation puts calls.
# The PC recorded is usually the return address (IP).
# Let's approximate by picking start of functions + 4? 
# Correct approach: `objdump -d --no-show-raw-insn vmlinux | grep 'call.*<__sanitizer_cov_trace_pc>'`
# output: ffffffff81000000: call   ffffffff81xxx <__sanitizer_cov_trace_pc>
# We want ffffffff81000000 + 5 (size of call).

echo "Running objdump (this may take a minute)..."
objdump -d --no-show-raw-insn "$VMLINUX" | grep 'call.*<__sanitizer_cov_trace_pc>' | awk '{print $1}' | sed 's/://' > pcs.hex
# Convert hex to 0x format and add 0 (or 5? typically we want the PC *during* the call or after?)
# Symbolization usually works on the address of the instruction or return address.
# If we symbolizer the call instruction address, we get the line of the call.
# That's what we want.
# So just keeping the address is fine. (syzkaller might adjust, but for comparison we just need consistent input).

echo "Found $(wc -l < pcs.hex) PCs."

echo "Running llvm-symbolizer..."
# Ensure we output separators or handle stream.
# llvm-symbolizer with one address per line outputs frames then newline?
# Wait, we need to ensure inputs are formatted as 0x...
awk '{print "0x" $1}' pcs.hex > pcs.in

$LLVM_SYMBOLIZER --obj="$VMLINUX" --output-style=GNU --functions --inlining < pcs.in > llvm.out

echo "Running syz-sym-check (native)..."
$SYZ_SYM_CHECK -kernel_obj="$VMLINUX" < pcs.in > native.out

echo "Comparing outputs..."
# We expect exact match or close.
# Use diff.
if diff -u llvm.out native.out > diff.patch; then
    echo "SUCCESS: Outputs match exactly!"
else
    echo "FAILURE: Mismatches found."
    echo "See diff.patch for details."
    echo "Top 20 lines of diff:"
    head -n 20 diff.patch
    exit 1
fi
