package unused

import (
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"slices"
	"strings"

	"github.com/uudashr/iface/internal/directive"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the unused interface analyzer.
var Analyzer = newAnalyzer()

func newAnalyzer() *analysis.Analyzer {
	r := runner{}

	analyzer := &analysis.Analyzer{
		Name:     "unused",
		Doc:      "Identifies interfaces that are not used anywhere in the same package where the interface is defined",
		URL:      "https://pkg.go.dev/github.com/uudashr/iface/unused",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      r.run,
	}

	analyzer.Flags.BoolVar(&r.debug, "debug", false, "enable debug mode")
	analyzer.Flags.StringVar(&r.exclude, "exclude", "", "comma-separated list of packages to exclude from the check")

	return analyzer
}

type runner struct {
	debug   bool
	exclude string
}

func (r *runner) run(pass *analysis.Pass) (interface{}, error) {
	excludes := strings.Split(r.exclude, ",")
	if slices.Contains(excludes, pass.Pkg.Path()) {
		return nil, nil
	}

	inspect := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Collect all interface type declarations
	ifaceDecls := make(map[string]token.Pos)

	nodeFilter := []ast.Node{
		(*ast.GenDecl)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		decl, ok := n.(*ast.GenDecl)
		if !ok {
			return
		}

		if r.debug {
			fmt.Printf("GenDecl: %v specs=%d\n", decl.Tok, len(decl.Specs))
		}

		if decl.Tok != token.TYPE {
			return
		}

		for i, spec := range decl.Specs {
			if r.debug {
				fmt.Printf(" spec[%d]: %v %v\n", i, spec, reflect.TypeOf(spec))
			}

			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}

			_, ok = ts.Type.(*ast.InterfaceType)
			if !ok {
				return
			}

			if r.debug {
				fmt.Println(" Interface type declaration:", ts.Name.Name, ts.Pos())
			}

			dir := directive.ParseIgnore(decl.Doc)
			if dir != nil && dir.ShouldIgnore(pass.Analyzer.Name) {
				// skip due to ignore directive
				continue
			}

			ifaceDecls[ts.Name.Name] = ts.Pos()
		}
	})

	if r.debug {
		var ifaceNames []string
		for name := range ifaceDecls {
			ifaceNames = append(ifaceNames, name)
		}

		fmt.Println("Declared interfaces:", ifaceNames)
	}

	// Inspect whether the interface is used within the package
	nodeFilter = []ast.Node{
		(*ast.Ident)(nil),
	}

	inspect.Preorder(nodeFilter, func(n ast.Node) {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return
		}

		pos := ifaceDecls[ident.Name]
		if pos == ident.Pos() {
			// The identifier is the interface type declaration
			return
		}

		delete(ifaceDecls, ident.Name)
	})

	if r.debug {
		fmt.Printf("Package %s %s\n", pass.Pkg.Path(), pass.Pkg.Name())
	}

	for name, pos := range ifaceDecls {
		pass.Reportf(pos, "interface %s is declared but not used within the package", name)
	}

	return nil, nil
}
