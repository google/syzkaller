
package symbolizer

import "github.com/VerditeLabs/syzkaller/sys/targets"

type Frame struct {
	PC     uint64
	Func   string
	File   string
	Line   int
	Inline bool
}

type Symbolizer interface {
	Symbolize(bin string, pcs ...uint64) ([]Frame, error)
	Close()
}

func Make(target *targets.Target) Symbolizer {
	return &addr2Line{target: target}
}
