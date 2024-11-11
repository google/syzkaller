package rule

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/mgechev/revive/internal/typeparams"
	"github.com/mgechev/revive/lint"
)

// disabledChecks store ignored warnings types
type disabledChecks struct {
	Const            bool
	Function         bool
	Method           bool
	PrivateReceivers bool
	PublicInterfaces bool
	Stuttering       bool
	Type             bool
	Var              bool
}

const checkNamePrivateReceivers = "privateReceivers"
const checkNamePublicInterfaces = "publicInterfaces"
const checkNameStuttering = "stuttering"

// isDisabled returns true if the given check is disabled, false otherwise
func (dc *disabledChecks) isDisabled(checkName string) bool {
	switch checkName {
	case "var":
		return dc.Var
	case "const":
		return dc.Const
	case "function":
		return dc.Function
	case "method":
		return dc.Method
	case checkNamePrivateReceivers:
		return dc.PrivateReceivers
	case checkNamePublicInterfaces:
		return dc.PublicInterfaces
	case checkNameStuttering:
		return dc.Stuttering
	case "type":
		return dc.Type
	default:
		return false
	}
}

// ExportedRule lints given else constructs.
type ExportedRule struct {
	configured     bool
	stuttersMsg    string
	disabledChecks disabledChecks
	sync.Mutex
}

func (r *ExportedRule) configure(arguments lint.Arguments) {
	r.Lock()
	defer r.Unlock()
	if r.configured {
		return
	}
	r.configured = true

	r.disabledChecks = disabledChecks{PrivateReceivers: true, PublicInterfaces: true}
	r.stuttersMsg = "stutters"
	for _, flag := range arguments {
		switch flag := flag.(type) {
		case string:
			switch flag {
			case "checkPrivateReceivers":
				r.disabledChecks.PrivateReceivers = false
			case "disableStutteringCheck":
				r.disabledChecks.Stuttering = true
			case "sayRepetitiveInsteadOfStutters":
				r.stuttersMsg = "is repetitive"
			case "checkPublicInterface":
				r.disabledChecks.PublicInterfaces = false
			case "disableChecksOnConstants":
				r.disabledChecks.Const = true
			case "disableChecksOnFunctions":
				r.disabledChecks.Function = true
			case "disableChecksOnMethods":
				r.disabledChecks.Method = true
			case "disableChecksOnTypes":
				r.disabledChecks.Type = true
			case "disableChecksOnVariables":
				r.disabledChecks.Var = true
			default:
				panic(fmt.Sprintf("Unknown configuration flag %s for %s rule", flag, r.Name()))
			}
		default:
			panic(fmt.Sprintf("Invalid argument for the %s rule: expecting a string, got %T", r.Name(), flag))
		}
	}
}

// Apply applies the rule to given file.
func (r *ExportedRule) Apply(file *lint.File, args lint.Arguments) []lint.Failure {
	r.configure(args)

	var failures []lint.Failure
	if file.IsTest() {
		return failures
	}

	fileAst := file.AST

	walker := lintExported{
		file:    file,
		fileAst: fileAst,
		onFailure: func(failure lint.Failure) {
			failures = append(failures, failure)
		},
		genDeclMissingComments: make(map[*ast.GenDecl]bool),
		stuttersMsg:            r.stuttersMsg,
		disabledChecks:         r.disabledChecks,
	}

	ast.Walk(&walker, fileAst)

	return failures
}

// Name returns the rule name.
func (*ExportedRule) Name() string {
	return "exported"
}

type lintExported struct {
	file                   *lint.File
	fileAst                *ast.File
	lastGen                *ast.GenDecl
	genDeclMissingComments map[*ast.GenDecl]bool
	onFailure              func(lint.Failure)
	stuttersMsg            string
	disabledChecks         disabledChecks
}

func (w *lintExported) lintFuncDoc(fn *ast.FuncDecl) {
	if !ast.IsExported(fn.Name.Name) {
		return // func is unexported, nothing to do
	}

	kind := "function"
	name := fn.Name.Name
	isMethod := fn.Recv != nil && len(fn.Recv.List) > 0
	if isMethod {
		kind = "method"
		recv := typeparams.ReceiverType(fn)

		if !ast.IsExported(recv) && w.disabledChecks.PrivateReceivers {
			return
		}

		if commonMethods[name] {
			return
		}

		switch name {
		case "Len", "Less", "Swap":
			sortables := w.file.Pkg.Sortable()
			if sortables[recv] {
				return
			}
		}
		name = recv + "." + name
	}

	if w.disabledChecks.isDisabled(kind) {
		return
	}

	if fn.Doc == nil {
		w.onFailure(lint.Failure{
			Node:       fn,
			Confidence: 1,
			Category:   "comments",
			Failure:    fmt.Sprintf("exported %s %s should have comment or be unexported", kind, name),
		})
		return
	}

	s := normalizeText(fn.Doc.Text())
	prefix := fn.Name.Name + " "
	if !strings.HasPrefix(s, prefix) {
		w.onFailure(lint.Failure{
			Node:       fn.Doc,
			Confidence: 0.8,
			Category:   "comments",
			Failure:    fmt.Sprintf(`comment on exported %s %s should be of the form "%s..."`, kind, name, prefix),
		})
	}
}

func (w *lintExported) checkStutter(id *ast.Ident, thing string) {
	if w.disabledChecks.Stuttering {
		return
	}

	pkg, name := w.fileAst.Name.Name, id.Name
	if !ast.IsExported(name) {
		// unexported name
		return
	}
	// A name stutters if the package name is a strict prefix
	// and the next character of the name starts a new word.
	if len(name) <= len(pkg) {
		// name is too short to stutter.
		// This permits the name to be the same as the package name.
		return
	}
	if !strings.EqualFold(pkg, name[:len(pkg)]) {
		return
	}
	// We can assume the name is well-formed UTF-8.
	// If the next rune after the package name is uppercase or an underscore
	// the it's starting a new word and thus this name stutters.
	rem := name[len(pkg):]
	if next, _ := utf8.DecodeRuneInString(rem); next == '_' || unicode.IsUpper(next) {
		w.onFailure(lint.Failure{
			Node:       id,
			Confidence: 0.8,
			Category:   "naming",
			Failure:    fmt.Sprintf("%s name will be used as %s.%s by other packages, and that %s; consider calling this %s", thing, pkg, name, w.stuttersMsg, rem),
		})
	}
}

func (w *lintExported) lintTypeDoc(t *ast.TypeSpec, doc *ast.CommentGroup) {
	if w.disabledChecks.isDisabled("type") {
		return
	}

	if !ast.IsExported(t.Name.Name) {
		return
	}

	if doc == nil {
		w.onFailure(lint.Failure{
			Node:       t,
			Confidence: 1,
			Category:   "comments",
			Failure:    fmt.Sprintf("exported type %v should have comment or be unexported", t.Name),
		})
		return
	}

	s := normalizeText(doc.Text())
	articles := [...]string{"A", "An", "The", "This"}
	for _, a := range articles {
		if t.Name.Name == a {
			continue
		}
		if strings.HasPrefix(s, a+" ") {
			s = s[len(a)+1:]
			break
		}
	}

	// if comment starts with name of type and has some text after - it's ok
	expectedPrefix := t.Name.Name + " "
	if strings.HasPrefix(s, expectedPrefix) {
		return
	}

	w.onFailure(lint.Failure{
		Node:       doc,
		Confidence: 1,
		Category:   "comments",
		Failure:    fmt.Sprintf(`comment on exported type %v should be of the form "%s..." (with optional leading article)`, t.Name, expectedPrefix),
	})
}

func (w *lintExported) lintValueSpecDoc(vs *ast.ValueSpec, gd *ast.GenDecl, genDeclMissingComments map[*ast.GenDecl]bool) {
	kind := "var"
	if gd.Tok == token.CONST {
		kind = "const"
	}

	if w.disabledChecks.isDisabled(kind) {
		return
	}

	if len(vs.Names) > 1 {
		// Check that none are exported except for the first.
		for _, n := range vs.Names[1:] {
			if ast.IsExported(n.Name) {
				w.onFailure(lint.Failure{
					Category:   "comments",
					Confidence: 1,
					Failure:    fmt.Sprintf("exported %s %s should have its own declaration", kind, n.Name),
					Node:       vs,
				})
				return
			}
		}
	}

	// Only one name.
	name := vs.Names[0].Name
	if !ast.IsExported(name) {
		return
	}

	if vs.Doc == nil && gd.Doc == nil {
		if genDeclMissingComments[gd] {
			return
		}
		block := ""
		if kind == "const" && gd.Lparen.IsValid() {
			block = " (or a comment on this block)"
		}
		w.onFailure(lint.Failure{
			Confidence: 1,
			Node:       vs,
			Category:   "comments",
			Failure:    fmt.Sprintf("exported %s %s should have comment%s or be unexported", kind, name, block),
		})
		genDeclMissingComments[gd] = true
		return
	}
	// If this GenDecl has parens and a comment, we don't check its comment form.
	if gd.Doc != nil && gd.Lparen.IsValid() {
		return
	}
	// The relevant text to check will be on either vs.Doc or gd.Doc.
	// Use vs.Doc preferentially.
	var doc *ast.CommentGroup
	switch {
	case vs.Doc != nil:
		doc = vs.Doc
	case vs.Comment != nil && gd.Doc == nil:
		doc = vs.Comment
	default:
		doc = gd.Doc
	}

	prefix := name + " "
	s := normalizeText(doc.Text())
	if !strings.HasPrefix(s, prefix) {
		w.onFailure(lint.Failure{
			Confidence: 1,
			Node:       doc,
			Category:   "comments",
			Failure:    fmt.Sprintf(`comment on exported %s %s should be of the form "%s..."`, kind, name, prefix),
		})
	}
}

// normalizeText is a helper function that normalizes comment strings by:
// * removing one leading space
//
// This function is needed because ast.CommentGroup.Text() does not handle //-style and /*-style comments uniformly
func normalizeText(t string) string {
	return strings.TrimSpace(t)
}

func (w *lintExported) Visit(n ast.Node) ast.Visitor {
	switch v := n.(type) {
	case *ast.GenDecl:
		if v.Tok == token.IMPORT {
			return nil
		}
		// token.CONST, token.TYPE or token.VAR
		w.lastGen = v
		return w
	case *ast.FuncDecl:
		w.lintFuncDoc(v)
		if v.Recv == nil {
			// Only check for stutter on functions, not methods.
			// Method names are not used package-qualified.
			w.checkStutter(v.Name, "func")
		}
		// Don't proceed inside funcs.
		return nil
	case *ast.TypeSpec:
		// inside a GenDecl, which usually has the doc
		doc := v.Doc
		if doc == nil {
			doc = w.lastGen.Doc
		}
		w.lintTypeDoc(v, doc)
		w.checkStutter(v.Name, "type")

		if !w.disabledChecks.PublicInterfaces {
			if iface, ok := v.Type.(*ast.InterfaceType); ok {
				if ast.IsExported(v.Name.Name) {
					w.doCheckPublicInterface(v.Name.Name, iface)
				}
			}
		}

		return nil
	case *ast.ValueSpec:
		w.lintValueSpecDoc(v, w.lastGen, w.genDeclMissingComments)
		return nil
	}
	return w
}

func (w *lintExported) doCheckPublicInterface(typeName string, iface *ast.InterfaceType) {
	for _, m := range iface.Methods.List {
		w.lintInterfaceMethod(typeName, m)
	}
}

func (w *lintExported) lintInterfaceMethod(typeName string, m *ast.Field) {
	if len(m.Names) == 0 {
		return
	}
	if !ast.IsExported(m.Names[0].Name) {
		return
	}
	name := m.Names[0].Name
	if m.Doc == nil {
		w.onFailure(lint.Failure{
			Node:       m,
			Confidence: 1,
			Category:   "comments",
			Failure:    fmt.Sprintf("public interface method %s.%s should be commented", typeName, name),
		})
		return
	}
	s := normalizeText(m.Doc.Text())
	expectedPrefix := m.Names[0].Name + " "
	if !strings.HasPrefix(s, expectedPrefix) {
		w.onFailure(lint.Failure{
			Node:       m.Doc,
			Confidence: 0.8,
			Category:   "comments",
			Failure:    fmt.Sprintf(`comment on exported interface method %s.%s should be of the form "%s..."`, typeName, name, expectedPrefix),
		})
	}
}
