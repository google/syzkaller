package protogetter

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"
)

type processor struct {
	info   *types.Info
	filter *PosFilter

	to   strings.Builder
	from strings.Builder
	err  error
}

func Process(info *types.Info, filter *PosFilter, n ast.Node) (*Result, error) {
	p := &processor{
		info:   info,
		filter: filter,
	}

	return p.process(n)
}

func (c *processor) process(n ast.Node) (*Result, error) {
	switch x := n.(type) {
	case *ast.AssignStmt:
		// Skip any assignment to the field.
		for _, lhs := range x.Lhs {
			c.filter.AddPos(lhs.Pos())
		}

	case *ast.IncDecStmt:
		// Skip any increment/decrement to the field.
		c.filter.AddPos(x.X.Pos())

	case *ast.UnaryExpr:
		if x.Op == token.AND {
			// Skip all expressions when the field is used as a pointer.
			// Because this is not direct reading, but most likely writing by pointer (for example like sql.Scan).
			c.filter.AddPos(x.X.Pos())
		}

	case *ast.CallExpr:
		f, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return &Result{}, nil
		}

		if !isProtoMessage(c.info, f.X) {
			return &Result{}, nil
		}

		c.processInner(x)

	case *ast.SelectorExpr:
		if !isProtoMessage(c.info, x.X) {
			// If the selector is not on a proto message, skip it.
			return &Result{}, nil
		}

		c.processInner(x)

	default:
		return nil, fmt.Errorf("not implemented for type: %s (%s)", reflect.TypeOf(x), formatNode(n))
	}

	if c.err != nil {
		return nil, c.err
	}

	return &Result{
		From: c.from.String(),
		To:   c.to.String(),
	}, nil
}

func (c *processor) processInner(expr ast.Expr) {
	switch x := expr.(type) {
	case *ast.Ident:
		c.write(x.Name)

	case *ast.BasicLit:
		c.write(x.Value)

	case *ast.UnaryExpr:
		if x.Op == token.AND {
			c.write(formatNode(x))
			return
		}

		c.write(x.Op.String())
		c.processInner(x.X)

	case *ast.SelectorExpr:
		c.processInner(x.X)
		c.write(".")

		// If getter exists, use it.
		if methodIsExists(c.info, x.X, "Get"+x.Sel.Name) {
			c.writeFrom(x.Sel.Name)
			c.writeTo("Get" + x.Sel.Name + "()")
			return
		}

		// If the selector is not a proto-message or the method has already been called, we leave it unchanged.
		// This approach is significantly more efficient than verifying the presence of methods in all cases.
		c.write(x.Sel.Name)

	case *ast.CallExpr:
		c.processInner(x.Fun)
		c.write("(")
		for i, arg := range x.Args {
			if i > 0 {
				c.write(",")
			}
			c.processInner(arg)
		}
		c.write(")")

	case *ast.IndexExpr:
		c.processInner(x.X)
		c.write("[")
		c.processInner(x.Index)
		c.write("]")

	case *ast.BinaryExpr:
		c.processInner(x.X)
		c.write(x.Op.String())
		c.processInner(x.Y)

	case *ast.ParenExpr:
		c.write("(")
		c.processInner(x.X)
		c.write(")")

	case *ast.StarExpr:
		c.write("*")
		c.processInner(x.X)

	case *ast.CompositeLit:
		c.write(formatNode(x))

	case *ast.TypeAssertExpr:
		c.write(formatNode(x))

	default:
		c.err = fmt.Errorf("processInner: not implemented for type: %s", reflect.TypeOf(x))
	}
}

func (c *processor) write(s string) {
	c.writeTo(s)
	c.writeFrom(s)
}

func (c *processor) writeTo(s string) {
	c.to.WriteString(s)
}

func (c *processor) writeFrom(s string) {
	c.from.WriteString(s)
}

// Result contains source code (from) and suggested change (to)
type Result struct {
	From string
	To   string
}

func (r *Result) Skipped() bool {
	// If from and to are the same, skip it.
	return r.From == r.To
}

func isProtoMessage(info *types.Info, expr ast.Expr) bool {
	// First, we are checking for the presence of the ProtoReflect method which is currently being generated
	// and corresponds to v2 version.
	// https://pkg.go.dev/google.golang.org/protobuf@v1.31.0/proto#Message
	const protoV2Method = "ProtoReflect"
	ok := methodIsExists(info, expr, protoV2Method)
	if ok {
		return true
	}

	// Afterwards, we are checking the ProtoMessage method. All the structures that implement the proto.Message interface
	// have a ProtoMessage method and are proto-structures. This interface has been generated since version 1.0.0 and
	// continues to exist for compatibility.
	// https://pkg.go.dev/github.com/golang/protobuf/proto?utm_source=godoc#Message
	const protoV1Method = "ProtoMessage"
	ok = methodIsExists(info, expr, protoV1Method)
	if ok {
		// Since there is a protoc-gen-gogo generator that implements the proto.Message interface, but may not generate
		// getters or generate from without checking for nil, so even if getters exist, we skip them.
		const protocGenGoGoMethod = "MarshalToSizedBuffer"
		return !methodIsExists(info, expr, protocGenGoGoMethod)
	}

	return false
}

func methodIsExists(info *types.Info, x ast.Expr, name string) bool {
	if info == nil {
		return false
	}

	t := info.TypeOf(x)
	if t == nil {
		return false
	}

	ptr, ok := t.Underlying().(*types.Pointer)
	if ok {
		t = ptr.Elem()
	}

	named, ok := t.(*types.Named)
	if !ok {
		return false
	}

	for i := 0; i < named.NumMethods(); i++ {
		if named.Method(i).Name() == name {
			return true
		}
	}

	return false
}
