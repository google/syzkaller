// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package linux

import (
	"flag"
	"fmt"
	"math/rand"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// AF_ALG tests won't generally pass and intended for manual testing.
// First, they require fresh kernel with _all_ crypto algorithms enabled.
// Second, they require the newest hardware with all of SSE/AVX.
// Finally, they still won't pass because some algorithms are arch-dependent.
var flagRunAlgTests = flag.Bool("algtests", false, "run AF_ALG tests")

func algTest(t *testing.T) {
	if !*flagRunAlgTests {
		t.Skip()
	}
	t.Parallel()
}

// TestAlgDescriptions checks that there are no duplicate names and that
// templates mentioned in complete algorithms are also present as standalone templates.
func TestAlgDescriptions(t *testing.T) {
	algTest(t)
	allall := make(map[string]bool)
	for typ, algList := range allAlgs {
		algs := make(map[string]bool)
		templates := make(map[string]bool)
		for _, alg := range algList {
			allall[alg.name] = true
			if algs[alg.name] {
				t.Errorf("duplicate: %v", alg.name)
			}
			algs[alg.name] = true
			if len(alg.args) > 0 {
				templates[alg.name] = true
			}
		}
		for _, alg := range algList {
			if len(alg.args) > 0 || strings.HasPrefix(alg.name, "__") {
				continue
			}
			brace := strings.IndexByte(alg.name, '(')
			if brace == -1 {
				continue
			}
			templ := alg.name[:brace]
			if !templates[templ] {
				t.Errorf("template %v is missing for type %v", templ, typ)
			}
			templates[templ] = true
		}
	}
}

// TestSingleAlg tests creation of all algorithms (not templates).
func TestSingleAlg(t *testing.T) {
	algTest(t)
	for _, typ := range allTypes {
		for _, alg := range allAlgs[typ.typ] {
			if len(alg.args) != 0 {
				continue
			}
			ok, skip := testAlg(t, typ.name, alg.name)
			if skip {
				t.Errorf("SKIP\t%10v\t%v", typ.name, alg.name)
				continue
			}
			if !ok {
				t.Errorf("FAIL\t%10v\t%v", typ.name, alg.name)
				continue
			}
		}
	}
}

// TestTemplateAlg1 tests creation of all templates with 1 argument.
func TestTemplateAlg1(t *testing.T) {
	algTest(t)
	for _, typ := range allTypes {
		for _, alg := range allAlgs[typ.typ] {
			if len(alg.args) != 1 {
				continue
			}
			var works []int
		nextType:
			for typ1, algs1 := range allAlgs {
				var selection []algDesc
				for _, x := range rand.Perm(len(algs1)) {
					if len(algs1[x].args) != 0 {
						continue
					}
					selection = append(selection, algs1[x])
					if len(selection) == 10 {
						break
					}
				}
				for _, alg1 := range selection {
					name := fmt.Sprintf("%v(%v)", alg.name, alg1.name)
					ok, _ := testAlg(t, typ.name, name)
					if ok {
						works = append(works, typ1)
						continue nextType
					}
				}
			}
			if len(works) == 1 && works[0] == alg.args[0] {
				continue
			}
			t.Errorf("FAIL\t%10v\t%v\tclaimed %v works with %v",
				typ.name, alg.name, alg.args[0], works)
		}
	}
}

// TestTemplateAlg2 tests creation of all templates with 2 argument.
func TestTemplateAlg2(t *testing.T) {
	algTest(t)
	// Can't afford to test all permutations of 2 algorithms,
	// 20 algorithm pairs for each type pair and use them.
	selections := make(map[int][]int)
	for typ1, algs1 := range allAlgs {
		for typ2, algs2 := range allAlgs {
			var pairs []int
			for i1, alg1 := range algs1 {
				if len(alg1.args) != 0 {
					continue
				}
				for i2, alg2 := range algs2 {
					if len(alg2.args) != 0 {
						continue
					}
					pairs = append(pairs, i1*1000+i2)
				}
			}
			var selection []int
			for _, x := range rand.Perm(len(pairs)) {
				selection = append(selection, pairs[x])
				if len(selection) > 20 {
					break
				}
			}
			selections[typ1*1000+typ2] = selection
		}
	}
	for _, typ := range allTypes {
		for _, alg := range allAlgs[typ.typ] {
			if len(alg.args) != 2 {
				continue
			}
			for typ1, algs1 := range allAlgs {
				for typ2, algs2 := range allAlgs {
					selection := selections[typ1*1000+typ2]
					for _, x := range selection {
						alg1 := algs1[x/1000]
						alg2 := algs2[x%1000]
						name := fmt.Sprintf("%v(%v,%v)",
							alg.name, alg1.name, alg2.name)
						if ok, _ := testAlg(t, typ.name, name); ok {
							t.Logf("%10v\t%v\tclaimed %v works with %v/%v (%v)",
								typ.name, alg.name, alg.args, typ1, typ2, name)
							break
						}
					}
				}
			}
		}
	}
}

type sockaddrAlg struct {
	family uint16
	typ    [14]byte
	feat   uint32
	mask   uint32
	name   [64]byte
}

func testAlg(t *testing.T, typ, name string) (ok, skip bool) {
	const AF_ALG = 0x26
	addr := &sockaddrAlg{
		family: AF_ALG,
		feat:   0,
		mask:   0,
	}
	if len(typ) >= int(unsafe.Sizeof(addr.typ)) ||
		len(name) >= int(unsafe.Sizeof(addr.name)) {
		return false, true
	}
	for i := 0; i < len(typ); i++ {
		addr.typ[i] = typ[i]
	}
	for i := 0; i < len(name); i++ {
		addr.name[i] = name[i]
	}
	sock, err := syscall.Socket(AF_ALG, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("failed to create AF_ALG socket: %v", err)
	}
	defer syscall.Close(sock)
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(sock),
		uintptr(unsafe.Pointer(addr)), unsafe.Sizeof(*addr))
	if errno != 0 {
		return false, false
	}
	return true, false
}
