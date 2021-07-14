// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// nolint: lll
//go:generate bash -c "gcc -DGOARCH_$GOARCH=1 kvm_gen.cc kvm_ppc64le.S -o kvm_gen && ./kvm_gen > kvm_ppc64le.S.h && rm ./kvm_gen"

package executor
