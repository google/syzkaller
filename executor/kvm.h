// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#define ADDR_TEXT 0x0000
#define ADDR_GDT 0x1000
#define ADDR_LDT 0x1800
#define ADDR_PML4 0x2000
#define ADDR_PDP 0x3000
#define ADDR_PD 0x4000
#define ADDR_STACK0 0x0f80
#define ADDR_VAR_HLT 0x2800
#define ADDR_VAR_SYSRET 0x2808
#define ADDR_VAR_SYSEXIT 0x2810
#define ADDR_VAR_IDT 0x3800
#define ADDR_VAR_TSS64 0x3a00
#define ADDR_VAR_TSS64_CPL3 0x3c00
#define ADDR_VAR_TSS16 0x3d00
#define ADDR_VAR_TSS16_2 0x3e00
#define ADDR_VAR_TSS16_CPL3 0x3f00
#define ADDR_VAR_TSS32 0x4800
#define ADDR_VAR_TSS32_2 0x4a00
#define ADDR_VAR_TSS32_CPL3 0x4c00
#define ADDR_VAR_TSS32_VM86 0x4e00
#define ADDR_VAR_VMXON_PTR 0x5f00
#define ADDR_VAR_VMCS_PTR 0x5f08
#define ADDR_VAR_VMEXIT_PTR 0x5f10
#define ADDR_VAR_VMWRITE_FLD 0x5f18
#define ADDR_VAR_VMWRITE_VAL 0x5f20
#define ADDR_VAR_VMXON 0x6000
#define ADDR_VAR_VMCS 0x7000
#define ADDR_VAR_VMEXIT_CODE 0x9000
#define ADDR_VAR_USER_CODE 0x9100
#define ADDR_VAR_USER_CODE2 0x9120

#define SEL_LDT (1 << 3)
#define SEL_CS16 (2 << 3)
#define SEL_DS16 (3 << 3)
#define SEL_CS16_CPL3 ((4 << 3) + 3)
#define SEL_DS16_CPL3 ((5 << 3) + 3)
#define SEL_CS32 (6 << 3)
#define SEL_DS32 (7 << 3)
#define SEL_CS32_CPL3 ((8 << 3) + 3)
#define SEL_DS32_CPL3 ((9 << 3) + 3)
#define SEL_CS64 (10 << 3)
#define SEL_DS64 (11 << 3)
#define SEL_CS64_CPL3 ((12 << 3) + 3)
#define SEL_DS64_CPL3 ((13 << 3) + 3)
#define SEL_CGATE16 (14 << 3)
#define SEL_TGATE16 (15 << 3)
#define SEL_CGATE32 (16 << 3)
#define SEL_TGATE32 (17 << 3)
#define SEL_CGATE64 (18 << 3)
#define SEL_CGATE64_HI (19 << 3)
#define SEL_TSS16 (20 << 3)
#define SEL_TSS16_2 (21 << 3)
#define SEL_TSS16_CPL3 ((22 << 3) + 3)
#define SEL_TSS32 (23 << 3)
#define SEL_TSS32_2 (24 << 3)
#define SEL_TSS32_CPL3 ((25 << 3) + 3)
#define SEL_TSS32_VM86 (26 << 3)
#define SEL_TSS64 (27 << 3)
#define SEL_TSS64_HI (28 << 3)
#define SEL_TSS64_CPL3 ((29 << 3) + 3)
#define SEL_TSS64_CPL3_HI (30 << 3)

#define MSR_IA32_FEATURE_CONTROL 0x3a
#define MSR_IA32_VMX_BASIC 0x480
#define MSR_IA32_SMBASE 0x9e
#define MSR_IA32_SYSENTER_CS 0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_STAR 0xC0000081
#define MSR_IA32_LSTAR 0xC0000082
#define MSR_IA32_VMX_PROCBASED_CTLS2 0x48B

#define NEXT_INSN $0xbadc0de
#define PREFIX_SIZE 0xba1d
