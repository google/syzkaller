#!/bin/sh
# Copyright 2025 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
#
# This script scans the syz-executor binary for data relocations accesses
# within the "guest" ELF section that are problematic for the SYZOS guest
# code.
#
# It uses $TARGETOS and $TARGETARCH to locate the binary and determine the
# correct architecture.
#

set -e
export LC_ALL=C

SECTION_TO_CHECK="guest"

echoerr() {
    echo "$@" >&2
}

AWK_CMD="awk"
if command -v gawk > /dev/null; then
    AWK_CMD="gawk"
fi

if [ "$TARGETOS" != "linux" ]; then
    echo "[INFO] TARGETOS is '$TARGETOS', not 'linux'. Skipping check."
    exit 0
fi

if [ "$TARGETOS" != "$BUILDOS" ]; then
    echo "[INFO] TARGETOS is '$TARGETOS', not '$BUILDOS'. Skipping check."
    exit 0
fi

if [ -z "$TARGETARCH" ]; then
    echoerr "Error: \$TARGETARCH environment variable is not set."
    exit 1
fi

BINARY="bin/${TARGETOS}_${TARGETARCH}/syz-executor"

if [ ! -f "$BINARY" ]; then
    echoerr "Error: Binary not found at '$BINARY'"
    exit 1
fi

echoerr "--> Analyzing architecture '$TARGETARCH'..."
OBJDUMP_CMD=""

if [ "$TARGETARCH" = "amd64" ]; then
    ARCH="x86_64"
    if command -v x86_64-linux-gnu-objdump > /dev/null; then
        OBJDUMP_CMD="x86_64-linux-gnu-objdump"
    fi
elif [ "$TARGETARCH" = "arm64" ]; then
    ARCH="aarch64"
    PATTERNS_TO_FIND='adrp'
    if command -v aarch64-linux-gnu-objdump > /dev/null; then
        OBJDUMP_CMD="aarch64-linux-gnu-objdump"
    fi
elif [ "$TARGETARCH" = "riscv64" ]; then
    ARCH="riscv64"
    PATTERNS_TO_FIND='auipc'
    if command -v riscv64-linux-gnu-objdump > /dev/null; then
        OBJDUMP_CMD="riscv64-linux-gnu-objdump"
    fi
elif [ "$TARGETARCH" = "loong64" ]; then
    ARCH="loongarch64"
    if command -v loongarch64-linux-gnu-objdump > /dev/null; then
        OBJDUMP_CMD="loongarch64-linux-gnu-objdump"
    fi
else
    echo "[INFO] Unsupported architecture '$TARGETARCH', skipping check."
    exit 0
fi
echoerr "--> Detected architecture: $ARCH"

if [ -z "$OBJDUMP_CMD" ]; then
    echoerr "--> Arch-specific objdump not found, falling back to generic 'objdump'..."
    if command -v objdump > /dev/null; then
        OBJDUMP_CMD="objdump"
    fi
fi

if [ -z "$OBJDUMP_CMD" ]; then
    echoerr "Error: Could not find a usable objdump binary."
    exit 1
fi
echoerr "--> Using objdump: $OBJDUMP_CMD"

echoerr "--> Verifying existence of section '$SECTION_TO_CHECK' in '$BINARY'..."
if ! SECTION_TABLE=$("$OBJDUMP_CMD" -h "$BINARY" 2>&1); then
    echoerr "Error: '$OBJDUMP_CMD' failed to read section headers from '$BINARY'."
    echoerr "$SECTION_TABLE"
    exit 1
fi

# Parse the section table once. An empty result means the binary has no guest
# section; malformed entries or awk failures remain errors.
if ! SECTION_INFO=$(printf '%s\n' "$SECTION_TABLE" | $AWK_CMD -v section="$SECTION_TO_CHECK" '
    $1 == "Idx" && $2 == "Name" && $3 == "Size" && $4 == "VMA" {
        table_found = 1
    }
    $2 == section {
        if (found || NF < 5 || $3 !~ /^[[:xdigit:]]+$/ || $4 !~ /^[[:xdigit:]]+$/)
            exit 2
        print $0
        found = 1
    }
    END {
        if (!table_found)
            exit 2
    }
'); then
    echoerr "Error: Could not parse section '$SECTION_TO_CHECK' from '$OBJDUMP_CMD' output."
    exit 1
fi
if [ -z "$SECTION_INFO" ]; then
    echo
    echo "[INFO] Section '$SECTION_TO_CHECK' not found in '$BINARY'. Skipping check."
    exit 0
fi

echoerr "--> Disassembling section '$SECTION_TO_CHECK' and scanning for problematic instructions..."

DISASSEMBLY_STATUS=0
DISASSEMBLY_OUTPUT=$("$OBJDUMP_CMD" -d --section="$SECTION_TO_CHECK" "$BINARY") || DISASSEMBLY_STATUS=$?

if [ "$DISASSEMBLY_STATUS" -ne 0 ]; then
    echoerr "Error: '$OBJDUMP_CMD' failed to disassemble the '$SECTION_TO_CHECK' section."
    exit 1
fi

case "$TARGETARCH" in
amd64|loong64)
    echoerr "--> Getting guest section boundaries..."
    GUEST_VMA=$(printf '%s\n' "$SECTION_INFO" | $AWK_CMD '{print "0x"$4}')
    GUEST_SIZE=$(printf '%s\n' "$SECTION_INFO" | $AWK_CMD '{print "0x"$3}')
    GUEST_START=$(printf "%d" "$GUEST_VMA")
    GUEST_END=$((GUEST_START + $(printf "%d" "$GUEST_SIZE")))
    echoerr "--> Guest section range (hex): [$(printf "0x%x" "$GUEST_START"), $(printf "0x%x" "$GUEST_END"))"
    FOUND_INSTRUCTIONS=$(printf '%s\n' "$DISASSEMBLY_OUTPUT" | $AWK_CMD \
        -v arch="$TARGETARCH" \
        -v guest_start="$GUEST_START" \
        -v guest_end="$GUEST_END" '
    # POSIX awk has no portable hexadecimal conversion function.
    function hex2dec(hex, value, i, digit) {
        if (hex == "")
            return -1
        value = 0
        hex = tolower(hex)
        for (i = 1; i <= length(hex); i++) {
            digit = index("0123456789abcdef", substr(hex, i, 1)) - 1
            if (digit < 0)
                return -1
            value = value * 16 + digit
        }
        return value
    }
    function report(clear_context) {
        if (current_func)
            print "In function <" current_func ">:"
        print "\t" $0
        if (clear_context)
            current_func = ""
    }
    /^[0-9a-f]+ <.*>:$/ {
        current_func = $0
        sub(/^[^<]*</, "", current_func)
        sub(/>:$/, "", current_func)
        next
    }
    arch == "amd64" && /\(%rip\)/ {
        target_hex = $0
        if (!sub(/^.*#[[:space:]]*/, "", target_hex))
            next
        sub(/[[:space:]].*$/, "", target_hex)
        target = hex2dec(target_hex)
        if (target < 0 || target < guest_start || target >= guest_end)
            report(0)
        next
    }
    # Match the address and mnemonic fields, not symbol names in comments.
    arch == "loong64" && $1 ~ /^[[:xdigit:]]+:$/ &&
        $3 ~ /^(pcaddi|pcalau12i|pcaddu12i|pcaddu18i)$/ {
        insn_addr_hex = $1
        sub(/:$/, "", insn_addr_hex)
        insn_addr = hex2dec(insn_addr_hex)
        insn = hex2dec($2)
        if ($3 == "pcaddi" && length($2) == 8 && insn_addr >= 0 && insn >= 0) {
            # PCADDI encodes a signed 20-bit word offset in bits 24:5.
            imm = int(insn / 32) % 1048576
            if (imm >= 524288)
                imm -= 1048576
            target = insn_addr + imm * 4
            if (target >= guest_start && target < guest_end)
                next
        }
        # Reject other PC-relative forms and malformed PCADDI encodings.
        report(1)
    }
')
    ;;
*)
    # The original logic for other architectures (e.g. arm64)
    FOUND_INSTRUCTIONS=$(echo "$DISASSEMBLY_OUTPUT" | $AWK_CMD -v pattern="$PATTERNS_TO_FIND" '
    # Match a function header, e.g., "0000000000401136 <my_func>:"
    /^[0-9a-f]+ <.*>:$/ {
        match($0, /<.*>/)
        current_func = substr($0, RSTART, RLENGTH)
    }
    # If the line matches the instruction pattern, print the context.
    $0 ~ pattern {
        if (current_func) {
            print "In function " current_func ":"
        }
        print "\t" $0
    }
')
    ;;
esac

if [ -n "$FOUND_INSTRUCTIONS" ]; then
    echo
    echo "------------------------------------------------------------------"
    echo "[FAIL] Found problematic data access instructions in '$SECTION_TO_CHECK'."
    echo "The following instructions are likely to cause crashes in SYZOS:"
    echo "$FOUND_INSTRUCTIONS" | sed 's/^/  /'
    echo "------------------------------------------------------------------"
    echo
    echo "This typically happens when the C compiler emits read-only constants for"
    echo "zero-initializing structs or for jump tables in switch statements."
    exit 1
else
    # Do not print anything to stdout unless there's an error.
    echoerr
    echoerr "[OK] No problematic data access instructions found in '$SECTION_TO_CHECK'."
    exit 0
fi
