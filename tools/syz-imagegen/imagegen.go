// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// imagegen generates syz_mount_image/syz_read_part_table calls from disk images.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

type Segment struct {
	offset int
	data   []byte
}

func main() {
	flagV := flag.Bool("v", false, "verbose output")
	flagImage := flag.String("image", "", "image file")
	flagSkip := flag.Int("skip", 32, "min zero bytes to skip")
	flagAlign := flag.Int("align", 32, "non-zero block alignment")
	flagFS := flag.String("fs", "", "filesystem")
	flag.Parse()
	data, err := ioutil.ReadFile(*flagImage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input file: %v\n", err)
		os.Exit(1)
	}
	data0 := data
	zeros := make([]byte, *flagAlign+*flagSkip)
	var segs []Segment
	offset := 0
	for len(data) != 0 {
		pos := bytes.Index(data, zeros)
		if pos == -1 {
			segs = append(segs, Segment{offset, data})
			break
		}
		pos = (pos + *flagAlign - 1) & ^(*flagAlign - 1)
		if pos != 0 {
			segs = append(segs, Segment{offset, data[:pos]})
		}
		for pos < len(data) && data[pos] == 0 {
			pos++
		}
		pos = pos & ^(*flagAlign - 1)
		offset += pos
		data = data[pos:]
	}
	totalData := 0
	for _, seg := range segs {
		totalData += len(seg.data)
	}
	fmt.Fprintf(os.Stderr, "image size: %v, segments: %v, data: %v\n",
		len(data0), len(segs), totalData)
	if *flagV {
		for i, seg := range segs {
			next := len(data0)
			if i != len(segs)-1 {
				next = segs[i+1].offset
			}
			skip := next - seg.offset - len(seg.data)
			fmt.Fprintf(os.Stderr, "segment: %8v-%8v [%8v] -%8v\n",
				seg.offset, seg.offset+len(seg.data), len(seg.data), skip)
		}
	}
	restored := make([]byte, len(data0))
	for _, seg := range segs {
		copy(restored[seg.offset:], seg.data)
	}
	if !bytes.Equal(data0, restored) {
		fmt.Fprintf(os.Stderr, "restored data differs!\n")
		os.Exit(1)
	}
	if *flagFS == "part" {
		fmt.Printf(`syz_read_part_table(0x%x, 0x%x, &(0x7f0000000200)=[`,
			len(data0), len(segs))
		addr := 0x7f0000010000
		for i, seg := range segs {
			if i != 0 {
				fmt.Printf(", ")
			}
			fmt.Printf(`{&(0x%x)="%v", 0x%x, 0x%x}`,
				addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
			addr = (addr + len(seg.data) + 0xff) & ^0xff
		}
		fmt.Printf("])\n")
	} else {
		syscallSuffix := *flagFS
		if syscallSuffix == "ext2" || syscallSuffix == "ext3" {
			syscallSuffix = "ext4"
		}
		fmt.Printf(`syz_mount_image$%v(&(0x7f0000000000)='%v\x00', &(0x7f0000000100)='./file0\x00',`+
			` 0x%x, 0x%x, &(0x7f0000000200)=[`,
			syscallSuffix, *flagFS, len(data0), len(segs))
		addr := 0x7f0000010000
		for i, seg := range segs {
			if i != 0 {
				fmt.Printf(", ")
			}
			fmt.Printf(`{&(0x%x)="%v", 0x%x, 0x%x}`,
				addr, hex.EncodeToString(seg.data), len(seg.data), seg.offset)
			addr = (addr + len(seg.data) + 0xff) & ^0xff
		}
		fmt.Printf("], 0x0, &(0x%x))\n", addr)
	}
}
