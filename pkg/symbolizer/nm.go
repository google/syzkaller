// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"bufio"
	"bytes"
	"strconv"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type Symbol struct {
	Addr uint64
	Size int
}

// ReadTextSymbols returns list of text symbols in the binary bin.
func (s *Symbolizer) ReadTextSymbols(bin string) (map[string][]Symbol, error) {
	return read(s.target, bin, "t", "T")
}

// ReadRodataSymbols returns list of rodata symbols in the binary bin.
func (s *Symbolizer) ReadRodataSymbols(bin string) (map[string][]Symbol, error) {
	return read(s.target, bin, "r", "R")
}

func read(target *targets.Target, bin string, types ...string) (map[string][]Symbol, error) {
	if len(types) != 2 || len(types[0]) != 1 || len(types[1]) != 1 {
		// We assume these things below.
		panic("bad types")
	}
	nm := "nm"
	if target != nil && target.Triple != "" {
		nm = target.Triple + "-" + nm
	}
	cmd := osutil.Command(nm, "-Ptx", bin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	symbols := make(map[string][]Symbol)
	s := bufio.NewScanner(stdout)
	var tt [][]byte
	for _, typ := range types {
		tt = append(tt, []byte(" "+typ+" "))
	}
	for s.Scan() {
		// A line looks as: "snb_uncore_msr_enable_box t ffffffff8104db90 0000000000000059"
		ln := s.Bytes()
		if !bytes.Contains(ln, tt[0]) && !bytes.Contains(ln, tt[1]) {
			continue
		}

		sp1 := bytes.IndexByte(ln, ' ')
		if sp1 == -1 {
			continue
		}
		if !bytes.HasPrefix(ln[sp1:], tt[0]) && !bytes.HasPrefix(ln[sp1:], tt[1]) {
			continue
		}

		sp2 := sp1 + len(tt[0])
		sp3 := bytes.IndexByte(ln[sp2:], ' ')
		if sp3 == -1 {
			continue
		}
		sp3 += sp2

		addr, err := strconv.ParseUint(string(ln[sp2:sp3]), 16, 64)
		if err != nil {
			continue
		}

		size, err := strconv.ParseUint(string(ln[sp3+1:]), 16, 64)
		if err != nil || size == 0 {
			continue
		}

		name := string(ln[:sp1])

		// Note: sizes reported by kernel do not match nm.
		// Kernel probably subtracts address of this symbol from address of the next symbol.
		// We could do the same, but for now we just round up size to 16.
		symbols[name] = append(symbols[name], Symbol{addr, int(size+15) / 16 * 16})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return symbols, nil
}
