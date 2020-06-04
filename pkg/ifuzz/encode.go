// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// See Intel Software Developer’s Manual Volume 2: Instruction Set Reference
// and AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System Instructions
// for details of instruction encoding.

package ifuzz

import (
	"math/rand"
)

// nolint: gocyclo, nestif, gocognit, funlen
func (insn *Insn) Encode(cfg *Config, r *rand.Rand) []byte {
	if !insn.isCompatible(cfg) {
		panic("instruction is not suitable for this mode")
	}
	if insn.Pseudo {
		return insn.generator(cfg, r)
	}

	var operSize, immSize, dispSize, addrSize int
	switch cfg.Mode {
	case ModeLong64:
		operSize, immSize, dispSize, addrSize = 4, 4, 4, 8
	case ModeProt32:
		operSize, immSize, dispSize, addrSize = 4, 4, 4, 4
	case ModeProt16, ModeReal16:
		operSize, immSize, dispSize, addrSize = 2, 2, 2, 2
	default:
		panic("bad mode")
	}

	var code []byte

	rexR := false
	var vvvv, vexR, vexX, vexB byte

	// LEGACY PREFIXES
	if insn.Vex == 0 {
		for r.Intn(3) == 0 {
			// LOCK 0xF0 is always added to insn.Prefix
			prefixes := []byte{
				0x2E, // CS
				0x3E, // DS
				0x26, // ES
				0x64, // FS
				0x65, // GS
				0x36, // SS
			}
			if !insn.No66Prefix {
				prefixes = append(prefixes, 0x66) // operand size
			}
			if cfg.Mode == ModeLong64 || !insn.Mem32 {
				prefixes = append(prefixes, 0x67) // address size
			}
			if !insn.NoRepPrefix {
				prefixes = append(prefixes,
					0xF3, // REP
					0xF2, // REPNE
				)
			}
			pref := prefixes[r.Intn(len(prefixes))]
			code = append(code, pref)
		}

		code = append(code, insn.Prefix...)

		// REX
		var rex byte
		if cfg.Mode == ModeLong64 && r.Intn(2) == 0 {
			// bit 0 - B
			// bit 1 - X
			// bit 2 - R
			// bit 3 - W
			rex = byte(0x40 | r.Intn(16))
			if insn.Rexw == 1 {
				rex |= 1 << 3
			} else {
				rex &^= 1 << 3
			}
			rexR = rex&0x4 != 0
			code = append(code, rex)
		}

		operSize1, immSize1, dispSize1, addrSize1 := operSize, immSize, dispSize, addrSize
		for _, pref := range code {
			switch pref {
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
			if rex&(1<<3) != 0 {
				operSize1 = 8
				immSize1 = 4
			}
		}
		operSize, immSize, dispSize, addrSize = operSize1, immSize1, dispSize1, addrSize1
	} else {
		// VEX/VOP
		code = append(code, insn.Vex)
		vexR = byte(1)
		vexX = byte(1)
		if cfg.Mode == ModeLong64 {
			vexR = byte(r.Intn(2))
			vexX = byte(r.Intn(2))
		}
		vexB = byte(r.Intn(2))
		W := byte(r.Intn(2))
		if insn.Rexw == 1 {
			W = 1
		} else if insn.Rexw == -1 {
			W = 0
		}
		L := byte(r.Intn(2))
		if insn.VexL == 1 {
			L = 1
		} else if insn.VexL == -1 {
			L = 0
		}
		pp := byte(r.Intn(4))
		if insn.VexP != -1 {
			pp = byte(insn.VexP)
		}
		vvvv = 15
		if !insn.VexNoR {
			vvvv = byte(r.Intn(16))
		}
		code = append(code, vexR<<7|vexX<<6|vexB<<5|insn.VexMap)
		code = append(code, W<<7|vvvv<<3|L<<2|pp)
		// TODO: short encoding
		if cfg.Mode != ModeLong64 {
			vvvv |= 8
		}
	}

	// OPCODE
	code = append(code, insn.Opcode...)

	if insn.Srm {
		rm := byte(insn.Rm)
		if insn.Rm == -1 {
			rm = byte(r.Intn(8))
		}
		code[len(code)-1] |= rm
	} else if insn.Modrm {
		// MODRM
		var mod byte
		switch insn.Mod {
		case 0, 1, 2, 3:
			mod = byte(insn.Mod)
		case -1:
			mod = byte(r.Intn(4))
		case -3:
			mod = byte(r.Intn(3))
		}

		reg := byte(insn.Reg)
		if insn.Reg == -1 {
			reg = byte(r.Intn(8))
		} else if insn.Reg == -6 {
			reg = byte(r.Intn(6)) // segment register
		} else if insn.Reg == -8 {
			if rexR {
				reg = 0 // CR8
			} else {
				crs := []byte{0, 2, 3, 4}
				reg = crs[r.Intn(len(crs))]
			}
		}
		if insn.Avx2Gather {
			if reg|(1-vexR)<<3 == vvvv^0xf {
				reg = (reg + 1) & 7
			}
		}

		rm := byte(insn.Rm)
		if insn.Rm == -1 {
			rm = byte(r.Intn(8))
		}

		modrm := mod<<6 | reg<<3 | rm
		code = append(code, modrm)

		if !insn.NoSibDisp {
			if addrSize == 2 {
				if mod == 1 {
					// disp8
					code = append(code, generateArg(cfg, r, 1)...)
				} else if mod == 2 || mod == 0 && rm == 6 {
					// disp16
					code = append(code, generateArg(cfg, r, 2)...)
				}
			} else {
				var sibbase byte
				if mod != 3 && rm == 4 {
					// SIB
					scale := byte(r.Intn(4))
					index := byte(r.Intn(8))
					sibbase = byte(r.Intn(8))
					if insn.Avx2Gather {
						rrrr := reg | (1-vexR)<<3
						for {
							iiii := index | (1-vexX)<<3
							if iiii != vvvv^0xf && iiii != rrrr {
								break
							}
							index = (index + 1) & 7
						}
					}
					sib := scale<<6 | index<<3 | sibbase
					code = append(code, sib)
				}

				if mod == 1 {
					// disp8
					code = append(code, generateArg(cfg, r, 1)...)
				} else if mod == 2 || mod == 0 && rm == 5 || mod == 0 && sibbase == 5 {
					// disp16/32
					code = append(code, generateArg(cfg, r, dispSize)...)
				}
			}
		}
	}

	addImm := func(imm int) {
		if imm == -1 {
			imm = immSize
		} else if imm == -2 {
			imm = addrSize
		} else if imm == -3 {
			imm = operSize
		}
		if imm != 0 {
			code = append(code, generateArg(cfg, r, imm)...)
		}
	}
	addImm(int(insn.Imm))
	addImm(int(insn.Imm2))

	code = append(code, insn.Suffix...)
	return code
}
