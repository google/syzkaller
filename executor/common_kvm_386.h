// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm
static long syz_kvm_setup_syzos_vm(volatile long a0, volatile long a1)
{
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
static long syz_kvm_add_vcpu(volatile long a0, volatile long a1)
{
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_uexit
static long syz_kvm_assert_syzos_uexit(volatile long a0, volatile long a1)
{
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	return 0;
}
#endif
