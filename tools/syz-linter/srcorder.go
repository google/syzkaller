// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"container/heap"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"slices"

	"golang.org/x/tools/go/analysis"
)

var SrcOrderAnalyzer = &analysis.Analyzer{
	Name: "srcorder",
	Doc:  "ensures natural for reading ordering of source code",
	Run:  srcorder,
}

func srcorder(pass *analysis.Pass) (any, error) {
	for _, ast := range pass.Files {
		filename := pass.Fset.File(ast.FileStart).Name()
		fc := &fileContext{
			pass:     pass,
			ast:      ast,
			filename: filename,
		}
		if err := fc.srcorder(); err != nil {
			return nil, fmt.Errorf("%v: %w", filename, err)
		}
	}
	return nil, nil
}

type fileContext struct {
	pass       *analysis.Pass
	ast        *ast.File
	filename   string
	filePrefix []byte
	fileSuffix []byte
	decls      []*declInfo
	names      map[types.Object]*declInfo
}

func (fc *fileContext) srcorder() error {
	fileData, err := fc.pass.ReadFile(fc.filename)
	if err != nil {
		return err
	}
	fc.extractDecls(fileData)
	fc.establishDeps()
	fc.transitiveClosure()
	fc.reorderDecls()
	if len(fc.decls) != len(fc.ast.Decls) {
		return fmt.Errorf("truncated file")
	}
	newSource := fc.writeNewSource()
	formatted, err := format.Source(newSource)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, newSource)
	}
	fc.emitDiagnostics(formatted)
	return nil
}

func (fc *fileContext) extractDecls(fileData []byte) {
	tokFile := fc.pass.Fset.File(fc.ast.Package)
	lastEnd := tokFile.Position(fc.ast.Name.End()).Offset
	for i, decl := range fc.ast.Decls {
		start := tokFile.Position(decl.Pos()).Offset
		end := tokFile.Position(decl.End()).Offset
		// Search backwards for the beginning of associated comments.
		// Doc comments are already attached if using parser.ParseComments.
		var doc *ast.CommentGroup
		if gd, ok := decl.(*ast.GenDecl); ok {
			doc = gd.Doc
		} else if fd, ok := decl.(*ast.FuncDecl); ok {
			doc = fd.Doc
		}
		if doc != nil {
			start = min(start, tokFile.Position(doc.Pos()).Offset)
			end = max(end, tokFile.Position(doc.End()).Offset)
		}
		// Also check standalone comments that appeared after the lastEnd,
		// and on the same line (trailing), and attach them to the next decl.
		nextLine := tokFile.End()
		if line := tokFile.Line(tokFile.Pos(end)); line < tokFile.LineCount() {
			nextLine = tokFile.LineStart(line + 1)
		}
		for _, cg := range fc.ast.Comments {
			if cg.Pos() > tokFile.Pos(lastEnd) && cg.Pos() < nextLine {
				start = min(start, tokFile.Position(cg.Pos()).Offset)
				end = max(end, tokFile.Position(cg.End()).Offset)
			}
		}
		fc.decls = append(fc.decls, &declInfo{
			decl:         decl,
			text:         fileData[start:end],
			index:        i,
			beforeReason: make(map[*declInfo]string),
			before:       make(map[*declInfo]bool),
			after:        make(map[*declInfo]bool),
			recv:         getReceiverTypeName(decl),
		})
		lastEnd = end
	}
	fc.filePrefix = fileData[:tokFile.Position(fc.ast.Name.End()).Offset]
	fc.fileSuffix = fileData[lastEnd:]
}

func (fc *fileContext) writeNewSource() []byte {
	buf := new(bytes.Buffer)
	buf.Write(fc.filePrefix)
	buf.WriteString("\n\n")
	for _, decl := range fc.decls {
		fmt.Fprintf(buf, "%s\n\n", decl.text)
	}
	buf.Write(fc.fileSuffix)
	return buf.Bytes()
}

type declInfo struct {
	decl ast.Decl
	// Capture exact source text for each declaration, including preceding comments.
	text []byte
	// Index in the original file, used as tie breaker.
	index int
	// For diagnostics printing.
	name string
	// Receiver type name for methods.
	recv string
	// Partial order we want to impose.
	beforeReason map[*declInfo]string
	// Transitive closure of beforeReason.
	before     map[*declInfo]bool
	after      map[*declInfo]bool
	isExported bool
	pending    int
}

func (fc *fileContext) establishDeps() {
	fc.names = make(map[types.Object]*declInfo)
	for _, decl := range fc.decls {
		noteName := func(id *ast.Ident) {
			fc.names[fc.pass.TypesInfo.Defs[id]] = decl
			if ast.IsExported(id.Name) {
				decl.isExported = true
			}
			if decl.name == "" {
				decl.name = id.Name
			}
		}
		switch d := decl.decl.(type) {
		case *ast.FuncDecl:
			noteName(d.Name)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					noteName(s.Name)
				}
			}
		}
	}
	for _, decl := range fc.decls {
		if decl.isFunc() {
			fc.establishFuncDeps(decl)
		}
		if decl.isStruct() {
			fc.establishStructDeps(decl)
		}
	}
}

func (fc *fileContext) establishFuncDeps(decl *declInfo) {
	// Enforce the following orderings:
	// - types used in function signatures should be declared before the function
	// - helper function used by another function should be declared after that function
	foreachUsedDecl := func(n ast.Node, fn func(*declInfo)) {
		ast.Inspect(n, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				// Nil selector means it's a name from another package.
				if fc.pass.TypesInfo.Selections[sel] == nil {
					return false
				}
			}
			if id, ok := n.(*ast.Ident); ok {
				if used := fc.findUse(id); used != nil {
					fn(used)
				}
			}
			return true
		})
	}
	signatureVisitor := func(n ast.Node) {
		foreachUsedDecl(n, func(used *declInfo) {
			if used.isType() {
				used.makeBefore(decl, "uses type in the signature")
			}
		})
	}
	fd := decl.decl.(*ast.FuncDecl)
	if fd.Recv != nil {
		signatureVisitor(fd.Recv)
	}
	if fd.Type.Params != nil {
		signatureVisitor(fd.Type.Params)
	}
	if fd.Type.Results != nil {
		signatureVisitor(fd.Type.Results)
	}
	if fd.Body != nil {
		foreachUsedDecl(fd.Body, func(used *declInfo) {
			if used.isFunc() {
				decl.makeBefore(used, "it's used in the body")
			}
		})
	}
}

func (decl *declInfo) isType() bool {
	gd, ok := decl.decl.(*ast.GenDecl)
	return ok && gd.Tok == token.TYPE
}

func (decl *declInfo) isFunc() bool {
	_, ok := decl.decl.(*ast.FuncDecl)
	return ok
}

func (fc *fileContext) establishStructDeps(decl *declInfo) {
	// Enforce the following ordering:
	// - struct types used as field types in another struct should be declared after that struct
	ast.Inspect(decl.decl, func(n ast.Node) bool {
		if _, ok := n.(*ast.SelectorExpr); ok {
			return false
		}
		if f, ok := n.(*ast.Field); ok {
			// Embed fields should not be moved after embeding struct.
			if f.Names != nil {
				if id, ok := f.Type.(*ast.Ident); ok {
					if used := fc.findUse(id); used != nil && used.isStruct() {
						decl.makeBefore(used, "it's a field type")
					}
				}
			}
			return false
		}
		return true
	})
}

func (decl *declInfo) isStruct() bool {
	gd, ok := decl.decl.(*ast.GenDecl)
	if ok && gd.Tok == token.TYPE && len(gd.Specs) == 1 {
		_, ok := gd.Specs[0].(*ast.TypeSpec).Type.(*ast.StructType)
		return ok
	}
	return false
}

// makeBefore notes that the decl must be placed before other.
func (decl *declInfo) makeBefore(other *declInfo, reason string) {
	if decl == other ||
		// Don't force unexported stuff before exported stuff.
		!decl.isExported && other.isExported ||
		// Don't reorder methods of the same type.
		decl.recv != "" && decl.recv == other.recv {
		return
	}
	decl.beforeReason[other] = reason
}

func (fc *fileContext) findUse(id *ast.Ident) *declInfo {
	return fc.names[fc.pass.TypesInfo.Uses[id]]
}

func (fc *fileContext) transitiveClosure() {
	for _, decl := range fc.decls {
		for other := range decl.beforeReason {
			decl.before[other] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, decl := range fc.decls {
			for other := range decl.before {
				for another := range other.before {
					if !decl.before[another] {
						decl.before[another] = true
						changed = true
					}
				}
			}
		}
	}
	for _, decl := range fc.decls {
		for other := range decl.before {
			other.after[decl] = true
		}
	}
}

func (fc *fileContext) emitDiagnostics(newSource []byte) {
	warned := map[*declInfo]bool{}
	for _, decl := range slices.Backward(fc.decls) {
		for other, reason := range decl.beforeReason {
			if other.index > decl.index || other.before[decl] || warned[other] {
				continue
			}
			warned[other] = true
			fc.pass.Report(analysis.Diagnostic{
				Pos: other.decl.Pos(),
				Message: fmt.Sprintf("Move %v after %v (:%v) b/c %v",
					other.name, decl.name, fc.pass.Fset.Position(decl.decl.Pos()).Line, reason),
			})
		}
	}
	if len(warned) != 0 {
		fc.pass.Report(analysis.Diagnostic{
			Pos:     fc.ast.FileStart,
			Message: "One or more declarations need to be reordered to provide natural reading order",
			SuggestedFixes: []analysis.SuggestedFix{{
				Message: "Rewritten file",
				TextEdits: []analysis.TextEdit{{
					Pos:     fc.ast.FileStart,
					End:     fc.ast.FileEnd,
					NewText: newSource,
				}},
			}},
		})
	}
}

type declHeap []*declInfo

func (h *declHeap) Len() int { return len(*h) }

func (h *declHeap) Less(i, j int) bool { return (*h)[i].index < (*h)[j].index }

func (h *declHeap) Swap(i, j int) { (*h)[i], (*h)[j] = (*h)[j], (*h)[i] }

func (h *declHeap) Push(x any) { *h = append(*h, x.(*declInfo)) }

func (h *declHeap) Pop() any {
	old := *h
	n := len(old) - 1
	x := old[n]
	old[n] = nil
	*h = old[:n]
	return x
}

func (fc *fileContext) reorderDecls() {
	// Reorder declarations according to hard dependencies (before),
	// but keeping the original order otherwise.
	// For this we keep a heap of declarations that are "ready" to be emitted
	// (all preceding hard deps are emitted), and the heap is ordered by decl.index (original order).
	ready := new(declHeap)
	for _, decl := range fc.decls {
		for other := range decl.after {
			// Break cyclic dependencies. Break the tie using the original index.
			// If decl has a smaller index, it refuses to wait for other.
			if other.after[decl] && decl.index <= other.index {
				continue
			}
			decl.pending++
		}
		if decl.pending == 0 {
			heap.Push(ready, decl)
		}
	}
	var result []*declInfo
	for ready.Len() > 0 {
		decl := heap.Pop(ready).(*declInfo)
		result = append(result, decl)
		for other := range decl.before {
			if decl.after[other] && other.index <= decl.index {
				continue // we ignored this dep in the loop above
			}
			other.pending--
			if other.pending == 0 {
				heap.Push(ready, other)
			}
		}
	}
	fc.decls = result
}

func getReceiverTypeName(decl ast.Decl) string {
	fd, ok := decl.(*ast.FuncDecl)
	if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	typ := fd.Recv.List[0].Type
	for {
		switch t := typ.(type) {
		case *ast.StarExpr:
			typ = t.X
		case *ast.IndexExpr:
			typ = t.X
		case *ast.IndexListExpr:
			typ = t.X
		case *ast.Ident:
			return t.Name
		default:
			panic(fmt.Sprintf("unhandled type %T", typ))
		}
	}
}
