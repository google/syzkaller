// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type DecompilerFlagMask uint64

// Extra flags that control the flow of decompilation.
const (
	FlagForceArmThumbMode DecompilerFlagMask = 1 << iota
)

const objdumpCallTimeout = 10 * time.Second

type DecompiledOpcode struct {
	Offset          int
	IsBad           bool
	Instruction     string
	FullDescription string
}

// Decompiles a byte array with opcodes into human-readable descriptions.
// Target must specify the environment from which the opcodes were taken.
func DecompileOpcodes(rawOpcodes []byte, flags DecompilerFlagMask, target *targets.Target) ([]DecompiledOpcode, error) {
	args, err := objdumpBuildArgs(flags, target)
	if err != nil {
		return nil, err
	}

	outBytes, err := objdumpExecutor(rawOpcodes, args, target)
	if err != nil {
		return nil, err
	}

	list := objdumpParseOutput(outBytes)
	if len(list) == 0 && len(rawOpcodes) > 0 {
		return nil, fmt.Errorf("no instructions found while the total size is %v bytes", len(rawOpcodes))
	}
	return list, nil
}

func objdumpExecutor(rawOpcodes []byte, args []string, target *targets.Target) ([]byte, error) {
	fileName, err := osutil.TempFile("syz-opcode-decompiler")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(fileName)

	err = osutil.WriteFile(fileName, rawOpcodes)
	if err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	return osutil.RunCmd(objdumpCallTimeout, "", target.Objdump, append(args, fileName)...)
}

// nolint: lll
var objdumpAsmLineRegexp = regexp.MustCompile(`\s+([a-fA-F0-9]+)\:\s+((?:[a-fA-F0-9]{2,8}\s*)*[a-fA-F0-9]{2,8})\s+(.*?)\s*$`)

func objdumpParseOutput(rawOutput []byte) []DecompiledOpcode {
	ret := []DecompiledOpcode{}
	for s := bufio.NewScanner(bytes.NewReader(rawOutput)); s.Scan(); {
		result := objdumpAsmLineRegexp.FindStringSubmatch(string(s.Bytes()))
		if result == nil {
			continue
		}
		offset, err := strconv.ParseUint(result[1], 16, 64)
		if err != nil {
			continue
		}
		const objdumpBadInstruction = "(bad)"
		ret = append(ret, DecompiledOpcode{
			Offset:          int(offset),
			IsBad:           result[3] == objdumpBadInstruction,
			Instruction:     result[3],
			FullDescription: strings.TrimRight(result[0], " \t"),
		})
	}
	return ret
}

func objdumpBuildArgs(flags DecompilerFlagMask, target *targets.Target) ([]string, error) {
	// objdump won't be able to decompile a raw binary file unless we specify the exact
	// architecture through the -m parameter.
	ret := []string{"-b", "binary", "-D"}
	switch target.Arch {
	case targets.ARM64:
		ret = append(ret, "-maarch64")
	case targets.ARM:
		ret = append(ret, "-marm")
		if flags&FlagForceArmThumbMode != 0 {
			ret = append(ret, "-M", "force-thumb")
		}
	case targets.I386:
		ret = append(ret, "-mi386")
	case targets.AMD64:
		ret = append(ret, "-mi386", "-Mx86-64")
	case targets.MIPS64LE:
		ret = append(ret, "-mmips")
	case targets.PPC64LE:
		ret = append(ret, "-mppc")
	case targets.S390x:
		ret = append(ret, "-m", "s390:64-bit")
	case targets.RiscV64:
		ret = append(ret, "-mriscv")
	default:
		return nil, fmt.Errorf("cannot build objdump args for %#v", target.Arch)
	}

	return ret, nil
}
