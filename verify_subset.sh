#!/bin/bash
# fast verification on subset
set -e

VMLINUX=${VMLINUX:-$HOME/projects/fuzzing-qemu/linux-stable/vmlinux}
SYZ_SYM_CHECK=./bin/syz-sym-check
LLVM_SYMBOLIZER=$(which llvm-symbolizer)

if [ ! -f "pcs.hex" ]; then
    echo "Running objdump..."
    objdump -d --no-show-raw-insn "$VMLINUX" | grep 'call.*<__sanitizer_cov_trace_pc>' | awk '{print $1}' | sed 's/://' > pcs.hex
fi

echo "Taking top 100 PCs..."
head -n 100 pcs.hex | awk '{print "0x" $1}' > pcs_subset.in

echo "Running llvm-symbolizer..."
$LLVM_SYMBOLIZER --obj="$VMLINUX" --output-style=GNU --functions --inlining -C < pcs_subset.in > llvm_subset.out

echo "Running syz-sym-check (native)..."
$SYZ_SYM_CHECK -kernel_obj="$VMLINUX" < pcs_subset.in > native_subset.out 2> native.err

echo "Native Stderr:"
cat native.err

echo "Comparing outputs..."
diff -u llvm_subset.out native_subset.out > diff_subset.patch || true
cat diff_subset.patch
