
// nolint: lll
//go:generate bash -c "gcc -Wa,--noexecstack -DGOARCH_$GOARCH=1 kvm_gen.cc kvm_amd64.S -o kvm_gen && ./kvm_gen > kvm_amd64.S.h && rm ./kvm_gen"

package executor
