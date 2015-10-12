# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

executor: executor.cc syscalls.h
	gcc executor.cc -o executor -lpthread -static -Wall -O1 -g

format: executor.cc
	clang-format --style=file -i executor.cc
	
