package zerologlint

import (
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"

	"github.com/gostaticanalysis/comment/passes/commentmap"
)

var Analyzer = &analysis.Analyzer{
	Name: "zerologlinter",
	Doc:  "finds cases where zerolog methods are not followed by Msg or Send",
	Run:  run,
	Requires: []*analysis.Analyzer{
		buildssa.Analyzer,
		commentmap.Analyzer,
	},
}

type posser interface {
	Pos() token.Pos
}

// posser is an interface just to hold both ssa.Call and ssa.Defer in our set
type callDefer interface {
	Common() *ssa.CallCommon
	Pos() token.Pos
}

func run(pass *analysis.Pass) (interface{}, error) {
	srcFuncs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs

	// This set holds all the ssa block that is a zerolog.Event type instance
	// that should be dispatched.
	// Everytime the zerolog.Event is dispatched with Msg() or Send(),
	// deletes that block from this set.
	// At the end, check if the set is empty, or report the not dispatched block.
	set := make(map[posser]struct{})

	for _, sf := range srcFuncs {
		for _, b := range sf.Blocks {
			for _, instr := range b.Instrs {
				if c, ok := instr.(*ssa.Call); ok {
					inspect(c, &set)
				} else if c, ok := instr.(*ssa.Defer); ok {
					inspect(c, &set)
				}
			}
		}
	}
	// At the end, if the set is clear -> ok.
	// Otherwise, there must be a left zerolog.Event var that weren't dispached. So report it.
	for k := range set {
		pass.Reportf(k.Pos(), "must be dispatched by Msg or Send method")
	}
	return nil, nil
}

func inspect(cd callDefer, set *map[posser]struct{}) {
	c := cd.Common()

	// check if it's in github.com/rs/zerolog/log since there's some
	// functions in github.com/rs/zerolog that returns zerolog.Event
	// which should not be included. However, zerolog.Logger receiver is an exception.
	if isInLogPkg(*c) || isLoggerRecv(*c) {
		if isZerologEvent(c.Value) {
			// this ssa block should be dispatched afterwards at some point
			(*set)[cd] = struct{}{}
			return
		}
	}

	// if the call does not return zerolog.Event,
	// check if the base is zerolog.Event.
	// if so, check if the StaticCallee is Send() or Msg().
	// if so, remove the arg[0] from the set.
	f := c.StaticCallee()
	if f == nil {
		return
	}
	if !isDispatchMethod(f) {
		shouldReturn := true
		for _, p := range f.Params {
			if isZerologEvent(p) {
				// check if this zerolog.Event as a parameter is dispatched in the function
				// TODO: specifically, it can be dispatched in another function that is called in this function, and
				//       this algorithm cannot track that. But I'm tired of thinking about that for now.
				for _, b := range f.Blocks {
					for _, instr := range b.Instrs {
						switch v := instr.(type) {
						case *ssa.Call:
							if inspectDispatchInFunction(v.Common()) {
								shouldReturn = false
							}
						case *ssa.Defer:
							if inspectDispatchInFunction(v.Common()) {
								shouldReturn = false
							}
						}
					}
				}
			}
		}
		if shouldReturn {
			return
		}
	}
	for _, arg := range c.Args {
		if isZerologEvent(arg) {
			val := getRootSsaValue(arg)
			// if there's branch, remove both ways from the set
			if phi, ok := val.(*ssa.Phi); ok {
				for _, edge := range phi.Edges {
					delete(*set, edge)
				}
			} else {
				delete(*set, val)
			}
		}
	}
}

func inspectDispatchInFunction(cc *ssa.CallCommon) bool {
	if isDispatchMethod(cc.StaticCallee()) {
		for _, arg := range cc.Args {
			if isZerologEvent(arg) {
				return true
			}
		}
	}
	return false
}

func isInLogPkg(c ssa.CallCommon) bool {
	switch v := c.Value.(type) {
	case ssa.Member:
		p := v.Package()
		if p == nil {
			return false
		}
		return strings.HasSuffix(p.Pkg.Path(), "github.com/rs/zerolog/log")
	}
	return false
}

func isLoggerRecv(c ssa.CallCommon) bool {
	switch f := c.Value.(type) {
	case *ssa.Function:
		if recv := f.Signature.Recv(); recv != nil {
			return strings.HasSuffix(types.TypeString(recv.Type(), nil), "zerolog.Logger")
		}
	}
	return false
}

func isZerologEvent(v ssa.Value) bool {
	ts := v.Type().String()
	return strings.HasSuffix(ts, "github.com/rs/zerolog.Event")
}

func isDispatchMethod(f *ssa.Function) bool {
	if f == nil {
		return false
	}
	m := f.Name()
	if m == "Send" || m == "Msg" || m == "Msgf" || m == "MsgFunc" {
		return true
	}
	return false
}

func getRootSsaValue(v ssa.Value) ssa.Value {
	if c, ok := v.(*ssa.Call); ok {
		v := c.Value()

		// When there is no receiver, that's the block of zerolog.Event
		// eg. Error() method in log.Error().Str("foo", "bar").Send()
		if len(v.Call.Args) == 0 {
			return v
		}

		// Even when there is a receiver, if it's a zerolog.Logger instance, return this block
		// eg. Info() method in zerolog.New(os.Stdout).Info()
		root := v.Call.Args[0]
		if !isZerologEvent(root) {
			return v
		}

		// Ok to just return the receiver because all the method in this
		// chain is zerolog.Event at this point.
		return getRootSsaValue(root)
	}
	return v
}
