// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
)

type Symbol struct {
	Addr uint64
	Size int
}

// ReadSymbols returns list of text symbols in the binary bin.
func ReadSymbols(bin string) (map[string][]Symbol, error) {
	cmd := exec.Command("nm", "-nS", bin)
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
	text := [][]byte{[]byte(" t "), []byte(" T ")}
	for s.Scan() {
		// A line looks as: "ffffffff8104db90 0000000000000059 t snb_uncore_msr_enable_box"
		ln := s.Bytes()
		if bytes.Index(ln, text[0]) == -1 && bytes.Index(ln, text[1]) == -1 {
			continue
		}
		sp1 := bytes.IndexByte(ln, ' ')
		if sp1 == -1 {
			continue
		}
		sp2 := bytes.IndexByte(ln[sp1+1:], ' ')
		if sp2 == -1 {
			continue
		}
		sp2 += sp1 + 1
		if !bytes.HasPrefix(ln[sp2:], text[0]) && !bytes.HasPrefix(ln[sp2:], text[1]) {
			continue
		}
		addr, err := strconv.ParseUint(string(ln[:sp1]), 16, 64)
		if err != nil {
			continue
		}
		size, err := strconv.ParseUint(string(ln[sp1+1:sp2]), 16, 64)
		if err != nil {
			continue
		}
		name := string(ln[sp2+len(text[0]):])
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
