// Package sloglint implements the sloglint analyzer.
package sloglint

import (
	"errors"
	"flag"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

// Options are options for the sloglint analyzer.
type Options struct {
	KVOnly         bool // Enforce using key-value pairs only (incompatible with AttrOnly).
	AttrOnly       bool // Enforce using attributes only (incompatible with KVOnly).
	NoRawKeys      bool // Enforce using constants instead of raw keys.
	ArgsOnSepLines bool // Enforce putting arguments on separate lines.
}

// New creates a new sloglint analyzer.
func New(opts *Options) *analysis.Analyzer {
	if opts == nil {
		opts = new(Options)
	}
	return &analysis.Analyzer{
		Name:     "sloglint",
		Doc:      "ensure consistent code style when using log/slog",
		Flags:    flags(opts),
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run: func(pass *analysis.Pass) (any, error) {
			if opts.KVOnly && opts.AttrOnly {
				return nil, errors.New("sloglint: incompatible options provided")
			}
			run(pass, opts)
			return nil, nil
		},
	}
}

func flags(opts *Options) flag.FlagSet {
	fs := flag.NewFlagSet("sloglint", flag.ContinueOnError)

	boolVar := func(value *bool, name, usage string) {
		fs.Func(name, usage, func(s string) error {
			v, err := strconv.ParseBool(s)
			*value = v
			return err
		})
	}

	boolVar(&opts.KVOnly, "kv-only", "enforce using key-value pairs only (incompatible with -attr-only)")
	boolVar(&opts.AttrOnly, "attr-only", "enforce using attributes only (incompatible with -kv-only)")
	boolVar(&opts.NoRawKeys, "no-raw-keys", "enforce using constants instead of raw keys")
	boolVar(&opts.ArgsOnSepLines, "args-on-sep-lines", "enforce putting arguments on separate lines")

	return *fs
}

var slogFuncs = map[string]int{ // funcName:argsPos
	"log/slog.Log":                    3,
	"log/slog.Debug":                  1,
	"log/slog.Info":                   1,
	"log/slog.Warn":                   1,
	"log/slog.Error":                  1,
	"log/slog.DebugContext":           2,
	"log/slog.InfoContext":            2,
	"log/slog.WarnContext":            2,
	"log/slog.ErrorContext":           2,
	"(*log/slog.Logger).Log":          3,
	"(*log/slog.Logger).Debug":        1,
	"(*log/slog.Logger).Info":         1,
	"(*log/slog.Logger).Warn":         1,
	"(*log/slog.Logger).Error":        1,
	"(*log/slog.Logger).DebugContext": 2,
	"(*log/slog.Logger).InfoContext":  2,
	"(*log/slog.Logger).WarnContext":  2,
	"(*log/slog.Logger).ErrorContext": 2,
}

var attrFuncs = map[string]struct{}{
	"log/slog.String":   {},
	"log/slog.Int64":    {},
	"log/slog.Int":      {},
	"log/slog.Uint64":   {},
	"log/slog.Float64":  {},
	"log/slog.Bool":     {},
	"log/slog.Time":     {},
	"log/slog.Duration": {},
	"log/slog.Group":    {},
	"log/slog.Any":      {},
}

func run(pass *analysis.Pass, opts *Options) {
	visit := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	filter := []ast.Node{(*ast.CallExpr)(nil)}

	visit.Preorder(filter, func(node ast.Node) {
		call := node.(*ast.CallExpr)

		fn := typeutil.StaticCallee(pass.TypesInfo, call)
		if fn == nil {
			return
		}

		argsPos, ok := slogFuncs[fn.FullName()]
		if !ok {
			return
		}

		// NOTE: we assume that the arguments have already been validated by govet.
		args := call.Args[argsPos:]
		if len(args) == 0 {
			return
		}

		var keys []ast.Expr
		var attrs []ast.Expr

		for i := 0; i < len(args); i++ {
			typ := pass.TypesInfo.TypeOf(args[i])
			if typ == nil {
				continue
			}
			switch typ.String() {
			case "string":
				keys = append(keys, args[i])
				i++ // skip the value.
			case "log/slog.Attr":
				attrs = append(attrs, args[i])
			}
		}

		switch {
		case opts.KVOnly && len(attrs) > 0:
			pass.Reportf(call.Pos(), "attributes should not be used")
		case opts.AttrOnly && len(attrs) < len(args):
			pass.Reportf(call.Pos(), "key-value pairs should not be used")
		case 0 < len(attrs) && len(attrs) < len(args):
			pass.Reportf(call.Pos(), "key-value pairs and attributes should not be mixed")
		}

		if opts.NoRawKeys && rawKeysUsed(pass.TypesInfo, keys, attrs) {
			pass.Reportf(call.Pos(), "raw keys should not be used")
		}
		if opts.ArgsOnSepLines && argsOnSameLine(pass.Fset, call, keys, attrs) {
			pass.Reportf(call.Pos(), "arguments should be put on separate lines")
		}
	})
}

func rawKeysUsed(info *types.Info, keys, attrs []ast.Expr) bool {
	isConst := func(expr ast.Expr) bool {
		ident, ok := expr.(*ast.Ident)
		return ok && ident.Obj != nil && ident.Obj.Kind == ast.Con
	}

	for _, key := range keys {
		if !isConst(key) {
			return true
		}
	}

	for _, attr := range attrs {
		switch attr := attr.(type) {
		case *ast.CallExpr: // e.g. slog.Int()
			fn := typeutil.StaticCallee(info, attr)
			if _, ok := attrFuncs[fn.FullName()]; ok && !isConst(attr.Args[0]) {
				return true
			}

		case *ast.CompositeLit: // slog.Attr{}
			isRawKey := func(kv *ast.KeyValueExpr) bool {
				return kv.Key.(*ast.Ident).Name == "Key" && !isConst(kv.Value)
			}

			switch len(attr.Elts) {
			case 1: // slog.Attr{Key: ...} | slog.Attr{Value: ...}
				kv := attr.Elts[0].(*ast.KeyValueExpr)
				if isRawKey(kv) {
					return true
				}
			case 2: // slog.Attr{..., ...} | slog.Attr{Key: ..., Value: ...}
				kv1, ok := attr.Elts[0].(*ast.KeyValueExpr)
				if ok {
					kv2 := attr.Elts[1].(*ast.KeyValueExpr)
					if isRawKey(kv1) || isRawKey(kv2) {
						return true
					}
				} else if !isConst(attr.Elts[0]) {
					return true
				}
			}
		}
	}

	return false
}

func argsOnSameLine(fset *token.FileSet, call ast.Expr, keys, attrs []ast.Expr) bool {
	if len(keys)+len(attrs) <= 1 {
		return false // special case: slog.Info("msg", "key", "value") is ok.
	}

	l := len(keys) + len(attrs) + 1
	args := make([]ast.Expr, 0, l)
	args = append(args, call)
	args = append(args, keys...)
	args = append(args, attrs...)

	lines := make(map[int]struct{}, l)
	for _, arg := range args {
		line := fset.Position(arg.Pos()).Line
		if _, ok := lines[line]; ok {
			return true
		}
		lines[line] = struct{}{}
	}

	return false
}
