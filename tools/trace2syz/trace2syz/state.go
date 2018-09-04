package trace2syz

import (
	"github.com/google/syzkaller/prog"
)

const (
	maxPages = 4 << 10
	PageSize = 4 << 10
)

type State struct {
	Target      *prog.Target
	Files       map[string][]*prog.Call
	Resources   map[string][]prog.Arg
	Strings     map[string]*prog.Call
	Pages       [maxPages]bool
	Tracker     *MemoryTracker
	CurrentCall *prog.Call
}

func newState(target *prog.Target) *State {
	s := &State{
		Target:      target,
		Files:       make(map[string][]*prog.Call),
		Resources:   make(map[string][]prog.Arg),
		Strings:     make(map[string]*prog.Call),
		Tracker:     newTracker(),
		CurrentCall: nil,
	}
	return s
}

func (s *State) analyze(c *prog.Call) {
	prog.ForeachArg(c, func(arg prog.Arg, _ *prog.ArgCtx) {
		switch typ := arg.Type().(type) {
		case *prog.ResourceType:
			a := arg.(*prog.ResultArg)
			if typ.Dir() != prog.DirIn {
				s.Resources[typ.Desc.Name] = append(s.Resources[typ.Desc.Name], a)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *prog.BufferType:
			a := arg.(*prog.DataArg)
			if typ.Dir() != prog.DirOut && len(a.Data()) != 0 {
				val := string(a.Data())
				// Remove trailing zero padding.
				for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
					val = val[:len(val)-1]
				}
				switch typ.Kind {
				case prog.BufferString:
					s.Strings[val] = c
				case prog.BufferFilename:
					if len(val) < 3 {
						// This is not our file, probalby one of specialFiles.
						return
					}
					/*
						if val[len(val)-1] == 0 {
							val = val[:len(val)-1]
						}*/
					if s.Files[val] == nil {
						s.Files[val] = make([]*prog.Call, 0)
					}
					s.Files[val] = append(s.Files[val], c)
				}
			}
		}
	})
}
