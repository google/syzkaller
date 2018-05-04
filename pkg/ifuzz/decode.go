// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"fmt"
)

// Decode decodes instruction length for the given mode.
// It can have falsely decode incorrect instructions,
// but should not fail to decode correct instructions.
// nolint: gocyclo
func Decode(mode int, text []byte) (int, error) {
	if len(text) == 0 {
		return 0, fmt.Errorf("zero-length instruction")
	}
	prefixes := prefixes32
	var operSize, immSize, dispSize, addrSize int
	switch mode {
	case ModeLong64:
		operSize, immSize, dispSize, addrSize = 4, 4, 4, 8
		prefixes = prefixes64
	case ModeProt32:
		operSize, immSize, dispSize, addrSize = 4, 4, 4, 4
	case ModeProt16, ModeReal16:
		operSize, immSize, dispSize, addrSize = 2, 2, 2, 2
	default:
		panic("bad mode")
	}
	prefixLen := 0
	var decodedPrefixes []byte
	vex := false
	if len(text) > 1 {
		// There are only 2 32-bit instructions that look like VEX-prefixed but are actually not: LDS, LES.
		// They always reference memory (mod!=3), but all VEX instructions have "mod=3" where LDS/LES would have mod.
		if (text[0] == 0xc4 || text[0] == 0xc5) && (mode == ModeLong64 || text[1]&0xc0 == 0xc0) {
			vex = true
		}
		// There is only one instruction that looks like XOP-prefixed but is actually not: POP.
		// It always has reg=0, but all XOP instructions have "reg!=0" where POP would have reg.
		if text[0] == 0x8f && text[1]&0x38 != 0 {
			vex = true
		}
	}
	var vexMap byte
	if vex {
		prefixLen = 3
		if text[0] == 0xc5 {
			prefixLen = 2
			vexMap = 1 // V0F
		}
		if len(text) < prefixLen {
			return 0, fmt.Errorf("bad VEX/XOP prefix")
		}
		if prefixLen == 3 {
			vexMap = text[1] & 0x1f
		}
		text = text[prefixLen:]
	} else {
		decodedPrefixes = text
		operSize1, immSize1, dispSize1, addrSize1 := operSize, immSize, dispSize, addrSize
		for len(text) != 0 && prefixes[text[0]] {
			switch text[0] {
			case 0x66:
				if immSize == 4 {
					immSize1 = 2
					operSize1 = 2
				} else if immSize == 2 {
					immSize1 = 4
					operSize1 = 4
				}
			case 0x67:
				if addrSize == 8 {
					addrSize1 = 4
				} else if addrSize == 4 {
					dispSize1 = 2
					addrSize1 = 2
				} else if addrSize == 2 {
					dispSize1 = 4
					addrSize1 = 4
				}
			}
			if text[0] & ^byte(7) == 0x48 {
				operSize1 = 8
				immSize1 = 4
			}
			text = text[1:]
			prefixLen++
		}
		operSize, immSize, dispSize, addrSize = operSize1, immSize1, dispSize1, addrSize1
		decodedPrefixes = decodedPrefixes[:prefixLen]
		if len(text) == 0 {
			return 0, fmt.Errorf("no opcode, only prefixes")
		}
	}
nextInsn:
	for _, insn := range modeInsns[mode][typeAll] {
		if vex != (insn.Vex != 0) {
			continue nextInsn
		}
		if vex && insn.VexMap != vexMap {
			continue nextInsn
		}
		if insn.NoRepPrefix || insn.No66Prefix {
			for _, p := range decodedPrefixes {
				if len(insn.Prefix) != 0 && insn.Prefix[0] == p {
					continue
				}
				switch p {
				case 0xf2, 0xf3:
					if insn.NoRepPrefix {
						continue nextInsn
					}
				case 0x66:
					if insn.No66Prefix {
						continue nextInsn
					}
				}
			}
		}
		text1 := text
		for i, v := range insn.Opcode {
			if len(text1) == 0 {
				continue nextInsn
			}
			b := text1[0]
			if insn.Srm && i == len(insn.Opcode)-1 {
				b &^= 7
			}
			if b != v {
				continue nextInsn
			}
			text1 = text1[1:]
		}
		if insn.Modrm {
			if len(text1) == 0 {
				continue nextInsn
			}
			modrm := text1[0]
			text1 = text1[1:]
			mod := modrm >> 6
			rm := modrm & 7
			if !insn.NoSibDisp {
				disp := 0
				if addrSize == 2 {
					if mod == 1 {
						disp = 1
					} else if mod == 2 || mod == 0 && rm == 6 {
						disp = 2
					}
				} else {
					var sibbase byte
					if mod != 3 && rm == 4 {
						if len(text1) == 0 {
							continue nextInsn
						}
						sib := text1[0]
						text1 = text1[1:]
						sibbase = sib & 7
					}
					if mod == 1 {
						disp = 1
					} else if mod == 2 || mod == 0 && rm == 5 || mod == 0 && sibbase == 5 {
						disp = dispSize
					}
				}
				if disp != 0 {
					if len(text1) < disp {
						continue nextInsn
					}
					text1 = text1[disp:]
				}
			}
		}
		immLen := 0
		for _, imm := range []int8{insn.Imm, insn.Imm2} {
			switch imm {
			case -1:
				immLen += immSize
			case -2:
				immLen += addrSize
			case -3:
				immLen += operSize
			default:
				immLen += int(imm)
			}
		}
		if immLen != 0 {
			if len(text1) < immLen {
				continue nextInsn
			}
			text1 = text1[immLen:]
		}
		for _, v := range insn.Suffix {
			if len(text1) == 0 || text1[0] != v {
				continue nextInsn
			}
			text1 = text1[1:]
		}
		return prefixLen + len(text) - len(text1), nil
	}
	return 0, fmt.Errorf("unknown instruction")
}

var XedDecode func(mode int, text []byte) (int, error)

var (
	prefixes32 = map[byte]bool{
		0x2E: true, 0x3E: true, 0x26: true, 0x64: true, 0x65: true,
		0x36: true, 0x66: true, 0x67: true, 0xF3: true, 0xF2: true,
		0xF0: true,
	}
	prefixes64 = map[byte]bool{
		0x2E: true, 0x3E: true, 0x26: true, 0x64: true, 0x65: true,
		0x36: true, 0x66: true, 0x67: true, 0xF3: true, 0xF2: true,
		0xF0: true, 0x40: true, 0x41: true, 0x42: true, 0x43: true,
		0x44: true, 0x45: true, 0x46: true, 0x47: true, 0x48: true,
		0x49: true, 0x4a: true, 0x4b: true, 0x4c: true, 0x4d: true,
		0x4e: true, 0x4f: true,
	}
)
