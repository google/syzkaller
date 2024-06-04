// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

func TestCreateBitmap(t *testing.T) {
	pcs := []uint64{
		0x81000002,
		0x8120001d,
	}
	target := targets.Get("test", "64")
	order := target.HostEndian
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			SysTarget: target,
		},
	}
	bitmap := createCoverageBitmap(cfg, pcs)
	start := order.Uint64(bitmap[0:])
	size := order.Uint64(bitmap[8:])
	if start != 0x81000002 || size != 0x20001b {
		t.Fatalf("bad region 0x%x/0x%x", start, size)
	}
	for i, byte := range bitmap[16:] {
		var expect uint8
		switch i {
		case 0:
			expect = 0x1
		case 0x20001 / 0x8:
			expect = 1 << (0x20001 % 0x8)
		}
		if byte != expect {
			t.Errorf("bad bitmap byte 0x%x: 0x%x, expect 0x%x", i, byte, expect)
		}
	}
	pcs = []uint64{
		0,
		0xffffffff,
	}
	createCoverageBitmap(cfg, pcs)
	pcs = []uint64{
		0x81000000,
		0x81000100,
	}
	createCoverageBitmap(cfg, pcs)
	pcs = []uint64{
		0x81000002,
		0x81000010,
		0x81000102,
	}
	createCoverageBitmap(cfg, pcs)
}

func TestNilCoverageBitmap(t *testing.T) {
	var pcs []uint64
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			SysTarget: targets.Get("test", "64"),
		},
	}
	bitmap := createCoverageBitmap(cfg, pcs)
	if bitmap != nil {
		t.Errorf("created a bitmap on nil pcs")
	}
}
