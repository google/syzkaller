// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"debug/elf"
	"fmt"
	"testing"
)

func TestGetTraceCallbackType(t *testing.T) {
	inputData := map[int][]string{
		TraceCbNone: {
			"foobar",
			"___sanitizer_cov_trace_pc",
		},
		TraceCbPc: {
			"__sanitizer_cov_trace_pc",
			"____sanitizer_cov_trace_pc_veneer",
		},
		TraceCbCmp: {
			"__sanitizer_cov_trace_cmp1",
			"__sanitizer_cov_trace_const_cmp4",
			"____sanitizer_cov_trace_const_cmp4_veneer",
		},
	}
	for expected, names := range inputData {
		for _, name := range names {
			result := getTraceCallbackType(name)
			if result != expected {
				t.Fatalf("getTraceCallbackType(`%v`) unexpectedly returned %v", name, result)
			}
		}
	}
}

func makeSection(name string, flags elf.SectionFlag, size, addralign uint64) *elf.Section {
	s := elf.SectionHeader{
		Name:      name,
		Flags:     flags,
		Size:      size,
		Addralign: addralign,
	}
	return &elf.Section{
		SectionHeader: s,
	}
}

type ElfModuleLoadParams struct {
	isArm64             bool
	isKernel61OrEarlier bool
	text                *elf.Section
	sections            *[]*elf.Section
}

func elfModuleLoadHelper(t *testing.T, p ElfModuleLoadParams, expect uint64) {
	result := elfSimulateModuleLoad(p.text, *p.sections, p.isArm64, p.isKernel61OrEarlier)
	if result != expect {
		sect := ""
		for _, s := range *p.sections {
			sect += fmt.Sprintf("%v\n", s)
		}
		t.Fatalf("elfSimulateModuleLoad() returned 0x%x instead of 0x%x\nSections:\n%v", result, expect, sect)
	}
}

func TestElfSimulateModuleLoad(t *testing.T) {
	var sect []*elf.Section
	text := makeSection(".text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1000, 0x1)

	// Test the non-ARM64 path.
	params := ElfModuleLoadParams{
		isArm64:             false,
		isKernel61OrEarlier: false,
		text:                text,
		sections:            &sect,
	}
	// Trivial case: .text section is loaded at 0x0.
	sect = append(sect, text)
	elfModuleLoadHelper(t, params, 0x0)

	// .init and .exit sections are ignored, as well as sections with non-text flags.
	sect = nil
	sect = append(sect, makeSection(".init.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1000, 0x1))
	sect = append(sect, makeSection(".data", elf.SHF_ALLOC|elf.SHF_WRITE, 0x1000, 0x1000))
	sect = append(sect, text)
	sect = append(sect, makeSection(".exit.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1000, 0x1))
	elfModuleLoadHelper(t, params, 0x0)

	// .text section is loaded after another code section. Alignment of that section doesn't matter.
	sect = nil
	sect = append(sect, makeSection(".foobar.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x4, 0x10))
	sect = append(sect, text)
	elfModuleLoadHelper(t, params, 0x4)

	// .text section is loaded after two sections. Alignment of the second section matters.
	sect = nil
	sect = append(sect, makeSection(".foobar.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x4, 0x10))
	sect = append(sect, makeSection(".foobaz.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x4, 0x10))
	sect = append(sect, text)
	elfModuleLoadHelper(t, params, 0x14)

	// Same rules apply to non-default sections on ARM64.
	params.isArm64 = true
	elfModuleLoadHelper(t, params, 0x14)

	// module_frob_arch_sections() overrides size/alignment of .plt and .text.ftrace_trampoline.
	sect = nil
	sect = append(sect, makeSection(".plt", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1, 0x16))
	sect = append(sect, makeSection(".text.ftrace_trampoline", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1, 0x1))
	sect = append(sect, text)
	elfModuleLoadHelper(t, params, 0x18)

	// Older kernels add 12 extra bytes to .text.ftrace_trampoline.
	params.isKernel61OrEarlier = true
	elfModuleLoadHelper(t, params, 0x24)

	// Nothing matters in the presence of a section with sufficiently big alignment.
	sect = nil
	sect = append(sect, makeSection(".plt", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1, 0x16))
	sect = append(sect, makeSection(".text.ftrace_trampoline", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x1, 0x1))
	sect = append(sect, makeSection(".hyp.text", elf.SHF_ALLOC|elf.SHF_EXECINSTR, 0x0, 0x1000))
	sect = append(sect, text)
	elfModuleLoadHelper(t, params, 0x1000)
}
