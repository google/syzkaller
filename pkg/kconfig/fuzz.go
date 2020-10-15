// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

func FuzzParseExpr(data []byte) int {
	p := newParser(data, "expr")
	if !p.nextLine() {
		return 0
	}
	p.parseExpr()
	return 0
}
