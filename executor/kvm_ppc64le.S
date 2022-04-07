// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// kvm_gen.cc generates machine code from this file and saves it into kvm_ppc64le.S.h.

// +build

#include "kvm.h"

#define LOAD64(rn,name)         \
    lis     rn,name##@highest;  \
    ori     rn,rn,name##@higher;    \
    rldicr  rn,rn,32,31;        \
    oris    rn,rn,name##@h;     \
    ori     rn,rn,name##@l

.global kvm_ppc64_mr, kvm_ppc64_mr_end
kvm_ppc64_mr:
	LOAD64(5, 0xbadc0de)
	mr      4,5
	mr      3,4
kvm_ppc64_mr_end:

.global kvm_ppc64_ld, kvm_ppc64_ld_end
kvm_ppc64_ld:
	LOAD64(15, 0xbadc0de)
	// Last double word of vma[24]
	LOAD64(25, 24 * 0x10000 - 8)
	std	15, 0(25)
	ld	3, 0(25)
kvm_ppc64_ld_end:

.global kvm_ppc64_recharge_dec, kvm_ppc64_recharge_dec_end
kvm_ppc64_recharge_dec:
	LOAD64(20,0x7ffffff)
#define SPRN_DEC        0x016           /* Decrement Register */
	mtspr SPRN_DEC,20
	rfid
kvm_ppc64_recharge_dec_end:
