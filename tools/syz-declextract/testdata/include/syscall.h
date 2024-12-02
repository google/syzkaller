// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#define SYSCALL_DEFINE1(NAME, ...) SYSCALL_DEFINEx(1, NAME, __VA_ARGS__)
#define SYSCALL_DEFINE2(NAME, ...) SYSCALL_DEFINEx(2, NAME, __VA_ARGS__)
#define SYSCALL_DEFINEx(NARGS, NAME, ...) long __do_sys_##NAME(__VA_ARGS__); \
long __do_sys_##NAME(__VA_ARGS__)
