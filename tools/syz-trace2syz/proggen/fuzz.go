
//go:build !codeanalysis

package proggen

import (
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var linuxTarget = func() *prog.Target {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		panic(err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	return target
}()

func Fuzz(data []byte) int {
	progs, err := ParseData(data, linuxTarget)
	if err != nil {
		return 0
	}
	return len(progs)
}
