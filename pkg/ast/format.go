// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bytes"
	"fmt"
	"io"
)

func Format(desc *Description) []byte {
	buf := new(bytes.Buffer)
	FormatWriter(buf, desc)
	return buf.Bytes()
}

func FormatWriter(w io.Writer, desc *Description) {
	for _, n := range desc.Nodes {
		s, ok := n.(serializer)
		if !ok {
			panic(fmt.Sprintf("unknown top level decl: %#v", n))
		}
		s.serialize(w)
	}
}

func SerializeNode(n Node) string {
	s, ok := n.(serializer)
	if !ok {
		panic(fmt.Sprintf("unknown node: %#v", n))
	}
	buf := new(bytes.Buffer)
	s.serialize(buf)
	return buf.String()
}

func FormatInt(v uint64, format IntFmt) string {
	switch format {
	case IntFmtDec:
		return fmt.Sprint(v)
	case IntFmtNeg:
		return fmt.Sprint(int64(v))
	case IntFmtHex:
		return fmt.Sprintf("0x%x", v)
	case IntFmtChar:
		return fmt.Sprintf("'%c'", v)
	default:
		panic(fmt.Sprintf("unknown int format %v", format))
	}
}

func FormatStr(v string, format StrFmt) string {
	switch format {
	case StrFmtRaw:
		return fmt.Sprintf(`"%v"`, v)
	case StrFmtHex:
		return fmt.Sprintf("`%x`", v)
	default:
		panic(fmt.Sprintf("unknown str format %v", format))
	}
}

type serializer interface {
	serialize(w io.Writer)
}

func (n *NewLine) serialize(w io.Writer) {
	fmt.Fprintf(w, "\n")
}

func (n *Comment) serialize(w io.Writer) {
	fmt.Fprintf(w, "#%v\n", n.Text)
}

func (n *Include) serialize(w io.Writer) {
	fmt.Fprintf(w, "include <%v>\n", n.File.Value)
}

func (n *Incdir) serialize(w io.Writer) {
	fmt.Fprintf(w, "incdir <%v>\n", n.Dir.Value)
}

func (n *Define) serialize(w io.Writer) {
	fmt.Fprintf(w, "define %v\t%v\n", n.Name.Name, fmtInt(n.Value))
}

func (n *Resource) serialize(w io.Writer) {
	fmt.Fprintf(w, "resource %v[%v]", n.Name.Name, fmtType(n.Base))
	for i, v := range n.Values {
		fmt.Fprintf(w, "%v%v", comma(i, ": "), fmtInt(v))
	}
	fmt.Fprintf(w, "\n")
}

func (n *TypeDef) serialize(w io.Writer) {
	fmt.Fprintf(w, "type %v%v", n.Name.Name, fmtIdentList(n.Args))
	if n.Type != nil {
		fmt.Fprintf(w, " %v\n", fmtType(n.Type))
	}
	if n.Struct != nil {
		n.Struct.serialize(w)
	}
}

func (n *Call) serialize(w io.Writer) {
	fmt.Fprintf(w, "%v(", n.Name.Name)
	for i, a := range n.Args {
		fmt.Fprintf(w, "%v%v", comma(i, ""), fmtField(a))
	}
	fmt.Fprintf(w, ")")
	if n.Ret != nil {
		fmt.Fprintf(w, " %v", fmtType(n.Ret))
	}
	if len(n.Attrs) != 0 {
		fmt.Fprintf(w, " %v", fmtTypeList(n.Attrs, "(", ")"))
	}
	fmt.Fprintf(w, "\n")
}

func (n *Struct) serialize(w io.Writer) {
	opening, closing := '{', '}'
	if n.IsUnion {
		opening, closing = '[', ']'
	}
	fmt.Fprintf(w, "%v %c\n", n.Name.Name, opening)
	// Align all field types to the same column.
	const tabWidth = 8
	maxTabs := 0
	for _, f := range n.Fields {
		tabs := (len(f.Name.Name) + tabWidth) / tabWidth
		if maxTabs < tabs {
			maxTabs = tabs
		}
	}
	for _, f := range n.Fields {
		if f.NewBlock {
			fmt.Fprintf(w, "\n")
		}
		for _, com := range f.Comments {
			fmt.Fprintf(w, "#%v\n", com.Text)
		}
		fmt.Fprintf(w, "\t%v\t", f.Name.Name)
		for tabs := len(f.Name.Name)/tabWidth + 1; tabs < maxTabs; tabs++ {
			fmt.Fprintf(w, "\t")
		}
		fmt.Fprintf(w, "%v", fmtType(f.Type))
		if len(f.Attrs) != 0 {
			fmt.Fprintf(w, "\t%v", fmtTypeList(f.Attrs, "(", ")"))
		}
		fmt.Fprintf(w, "\n")
	}
	for _, com := range n.Comments {
		fmt.Fprintf(w, "#%v\n", com.Text)
	}
	fmt.Fprintf(w, "%c", closing)
	if attrs := fmtTypeList(n.Attrs, "[", "]"); attrs != "" {
		fmt.Fprintf(w, " %v", attrs)
	}
	fmt.Fprintf(w, "\n")
}

func (n *IntFlags) serialize(w io.Writer) {
	fmt.Fprintf(w, "%v = ", n.Name.Name)
	for i, v := range n.Values {
		fmt.Fprintf(w, "%v%v", comma(i, ""), fmtInt(v))
	}
	fmt.Fprintf(w, "\n")
}

func (n *StrFlags) serialize(w io.Writer) {
	fmt.Fprintf(w, "%v = ", n.Name.Name)
	for i, v := range n.Values {
		fmt.Fprintf(w, "%v%v", comma(i, ""), FormatStr(v.Value, v.Fmt))
	}
	fmt.Fprintf(w, "\n")
}

func fmtField(f *Field) string {
	return fmt.Sprintf("%v %v", f.Name.Name, fmtType(f.Type))
}

func (n *Type) serialize(w io.Writer) {
	w.Write([]byte(fmtType(n)))
}

func fmtType(t *Type) string {
	v := ""
	switch {
	case t.Ident != "":
		v = t.Ident
	case t.HasString:
		v = FormatStr(t.String, t.StringFmt)
	default:
		v = FormatInt(t.Value, t.ValueFmt)
	}
	for _, c := range t.Colon {
		v += ":" + fmtType(c)
	}
	v += fmtTypeList(t.Args, "[", "]")
	return v
}

func fmtTypeList(args []*Type, opening, closing string) string {
	if len(args) == 0 {
		return ""
	}
	w := new(bytes.Buffer)
	fmt.Fprint(w, opening)
	for i, t := range args {
		fmt.Fprintf(w, "%v%v", comma(i, ""), fmtType(t))
	}
	fmt.Fprint(w, closing)
	return w.String()
}

func fmtIdentList(args []*Ident) string {
	if len(args) == 0 {
		return ""
	}
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "[")
	for i, arg := range args {
		fmt.Fprintf(w, "%v%v", comma(i, ""), arg.Name)
	}
	fmt.Fprintf(w, "]")
	return w.String()
}

func fmtInt(i *Int) string {
	switch {
	case i.Ident != "":
		return i.Ident
	case i.CExpr != "":
		return fmt.Sprintf("%v", i.CExpr)
	default:
		return FormatInt(i.Value, i.ValueFmt)
	}
}

func comma(i int, or string) string {
	if i == 0 {
		return or
	}
	return ", "
}
