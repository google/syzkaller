
package main

import (
	"fmt"

	"github.com/VerditeLabs/syzkaller/pkg/ast"
	"github.com/VerditeLabs/syzkaller/pkg/compiler"
)

// constsAreAllDefined() ensures that for every const there's at least one arch that defines it.
func constsAreAllDefined(consts *compiler.ConstFile, constInfo map[string]*compiler.ConstInfo,
	eh ast.ErrorHandler) {
	// We cannot perform this check inside pkg/compiler because it's
	// given a const slice for only one architecture.
	for _, info := range constInfo {
		for _, def := range info.Consts {
			if consts.ExistsAny(def.Name) {
				continue
			}
			eh(def.Pos, fmt.Sprintf("%s is defined for none of the arches", def.Name))
		}
	}
}
