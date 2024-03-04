// Package sloglint implements the sloglint analyzer.
package sloglint

import (
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"github.com/ettle/strcase"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/types/typeutil"
)

// Options are options for the sloglint analyzer.
type Options struct {
	NoMixedArgs    bool   // Enforce not mixing key-value pairs and attributes (default true).
	KVOnly         bool   // Enforce using key-value pairs only (overrides NoMixedArgs, incompatible with AttrOnly).
	AttrOnly       bool   // Enforce using attributes only (overrides NoMixedArgs, incompatible with KVOnly).
	ContextOnly    bool   // Enforce using methods that accept a context.
	StaticMsg      bool   // Enforce using static log messages.
	NoRawKeys      bool   // Enforce using constants instead of raw keys.
	KeyNamingCase  string // Enforce a single key naming convention ("snake", "kebab", "camel", or "pascal").
	ArgsOnSepLines bool   // Enforce putting arguments on separate lines.
}

// New creates a new sloglint analyzer.
func New(opts *Options) *analysis.Analyzer {
	if opts == nil {
		opts = &Options{NoMixedArgs: true}
	}
	return &analysis.Analyzer{
		Name:     "sloglint",
		Doc:      "ensure consistent code style when using log/slog",
		Flags:    flags(opts),
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run: func(pass *analysis.Pass) (any, error) {
			if opts.KVOnly && opts.AttrOnly {
				return nil, fmt.Errorf("sloglint: Options.KVOnly and Options.AttrOnly: %w", errIncompatible)
			}
			switch opts.KeyNamingCase {
			case "", snakeCase, kebabCase, camelCase, pascalCase:
			default:
				return nil, fmt.Errorf("sloglint: Options.KeyNamingCase=%s: %w", opts.KeyNamingCase, errInvalidValue)
			}
			run(pass, opts)
			return nil, nil
		},
	}
}

var (
	errIncompatible = errors.New("incompatible options")
	errInvalidValue = errors.New("invalid value")
)

func flags(opts *Options) flag.FlagSet {
	fs := flag.NewFlagSet("sloglint", flag.ContinueOnError)

	boolVar := func(value *bool, name, usage string) {
		fs.Func(name, usage, func(s string) error {
			v, err := strconv.ParseBool(s)
			*value = v
			return err
		})
	}

	boolVar(&opts.NoMixedArgs, "no-mixed-args", "enforce not mixing key-value pairs and attributes (default true)")
	boolVar(&opts.KVOnly, "kv-only", "enforce using key-value pairs only (overrides -no-mixed-args, incompatible with -attr-only)")
	boolVar(&opts.AttrOnly, "attr-only", "enforce using attributes only (overrides -no-mixed-args, incompatible with -kv-only)")
	boolVar(&opts.ContextOnly, "context-only", "enforce using methods that accept a context")
	boolVar(&opts.StaticMsg, "static-msg", "enforce using static log messages")
	boolVar(&opts.NoRawKeys, "no-raw-keys", "enforce using constants instead of raw keys")
	boolVar(&opts.ArgsOnSepLines, "args-on-sep-lines", "enforce putting arguments on separate lines")

	fs.Func("key-naming-case", "enforce a single key naming convention (snake|kebab|camel|pascal)", func(s string) error {
		opts.KeyNamingCase = s
		return nil
	})

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

const (
	snakeCase  = "snake"
	kebabCase  = "kebab"
	camelCase  = "camel"
	pascalCase = "pascal"
)

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

		if opts.ContextOnly {
			typ := pass.TypesInfo.TypeOf(call.Args[0])
			if typ != nil && typ.String() != "context.Context" {
				pass.Reportf(call.Pos(), "methods without a context should not be used")
			}
		}
		if opts.StaticMsg && !staticMsg(call.Args[argsPos-1]) {
			pass.Reportf(call.Pos(), "message should be a string literal or a constant")
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
		case opts.NoMixedArgs && 0 < len(attrs) && len(attrs) < len(args):
			pass.Reportf(call.Pos(), "key-value pairs and attributes should not be mixed")
		}

		if opts.NoRawKeys && rawKeysUsed(pass.TypesInfo, keys, attrs) {
			pass.Reportf(call.Pos(), "raw keys should not be used")
		}
		if opts.ArgsOnSepLines && argsOnSameLine(pass.Fset, call, keys, attrs) {
			pass.Reportf(call.Pos(), "arguments should be put on separate lines")
		}

		switch {
		case opts.KeyNamingCase == snakeCase && badKeyNames(pass.TypesInfo, strcase.ToSnake, keys, attrs):
			pass.Reportf(call.Pos(), "keys should be written in snake_case")
		case opts.KeyNamingCase == kebabCase && badKeyNames(pass.TypesInfo, strcase.ToKebab, keys, attrs):
			pass.Reportf(call.Pos(), "keys should be written in kebab-case")
		case opts.KeyNamingCase == camelCase && badKeyNames(pass.TypesInfo, strcase.ToCamel, keys, attrs):
			pass.Reportf(call.Pos(), "keys should be written in camelCase")
		case opts.KeyNamingCase == pascalCase && badKeyNames(pass.TypesInfo, strcase.ToPascal, keys, attrs):
			pass.Reportf(call.Pos(), "keys should be written in PascalCase")
		}
	})
}

func staticMsg(expr ast.Expr) bool {
	switch msg := expr.(type) {
	case *ast.BasicLit: // e.g. slog.Info("msg")
		return msg.Kind == token.STRING
	case *ast.Ident: // e.g. const msg = "msg"; slog.Info(msg)
		return msg.Obj != nil && msg.Obj.Kind == ast.Con
	default:
		return false
	}
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

func badKeyNames(info *types.Info, caseFn func(string) string, keys, attrs []ast.Expr) bool {
	for _, key := range keys {
		if name, ok := getKeyName(key); ok && name != caseFn(name) {
			return true
		}
	}

	for _, attr := range attrs {
		var expr ast.Expr
		switch attr := attr.(type) {
		case *ast.CallExpr: // e.g. slog.Int()
			fn := typeutil.StaticCallee(info, attr)
			if _, ok := attrFuncs[fn.FullName()]; ok {
				expr = attr.Args[0]
			}
		case *ast.CompositeLit: // slog.Attr{}
			switch len(attr.Elts) {
			case 1: // slog.Attr{Key: ...} | slog.Attr{Value: ...}
				if kv := attr.Elts[0].(*ast.KeyValueExpr); kv.Key.(*ast.Ident).Name == "Key" {
					expr = kv.Value
				}
			case 2: // slog.Attr{..., ...} | slog.Attr{Key: ..., Value: ...}
				expr = attr.Elts[0]
				if kv1, ok := attr.Elts[0].(*ast.KeyValueExpr); ok && kv1.Key.(*ast.Ident).Name == "Key" {
					expr = kv1.Value
				}
				if kv2, ok := attr.Elts[1].(*ast.KeyValueExpr); ok && kv2.Key.(*ast.Ident).Name == "Key" {
					expr = kv2.Value
				}
			}
		}
		if name, ok := getKeyName(expr); ok && name != caseFn(name) {
			return true
		}
	}

	return false
}

func getKeyName(expr ast.Expr) (string, bool) {
	if expr == nil {
		return "", false
	}
	if ident, ok := expr.(*ast.Ident); ok {
		if ident.Obj == nil || ident.Obj.Decl == nil || ident.Obj.Kind != ast.Con {
			return "", false
		}
		if spec, ok := ident.Obj.Decl.(*ast.ValueSpec); ok && len(spec.Values) > 0 {
			// TODO: support len(spec.Values) > 1; e.g. "const foo, bar = 1, 2"
			expr = spec.Values[0]
		}
	}
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return lit.Value, true
	}
	return "", false
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
