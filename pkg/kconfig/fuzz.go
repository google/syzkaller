
package kconfig

import (
	"github.com/VerditeLabs/syzkaller/sys/targets"
)

func FuzzParseKConfig(data []byte) int {
	ParseData(targets.Get("linux", "amd64"), data, "kconfig")
	return 0
}

func FuzzParseConfig(data []byte) int {
	ParseConfigData(data, "config")
	return 0
}

func FuzzParseExpr(data []byte) int {
	p := newParser(data, "expr")
	if !p.nextLine() {
		return 0
	}
	p.parseExpr()
	return 0
}
