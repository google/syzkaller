// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ast

import (
	"bytes"
	"fmt"
	"io"
)

func Format(top []interface{}) []byte {
	buf := new(bytes.Buffer)
	FormatWriter(buf, top)
	return buf.Bytes()
}

func FormatWriter(w io.Writer, top []interface{}) {
	for _, decl := range top {
		s, ok := decl.(serializer)
		if !ok {
			panic(fmt.Sprintf("unknown top level decl: %#v", decl))
		}
		s.Serialize(w)
	}
}

type serializer interface {
	Serialize(w io.Writer)
}

func (incl *NewLine) Serialize(w io.Writer) {
	fmt.Fprintf(w, "\n")
}

func (com *Comment) Serialize(w io.Writer) {
	fmt.Fprintf(w, "#%v\n", com.Text)
}

func (incl *Include) Serialize(w io.Writer) {
	fmt.Fprintf(w, "include <%v>\n", incl.File.Value)
}

func (inc *Incdir) Serialize(w io.Writer) {
	fmt.Fprintf(w, "incdir <%v>\n", inc.Dir.Value)
}

func (def *Define) Serialize(w io.Writer) {
	fmt.Fprintf(w, "define %v\t%v\n", def.Name.Name, fmtInt(def.Value))
}

func (res *Resource) Serialize(w io.Writer) {
	fmt.Fprintf(w, "resource %v[%v]", res.Name.Name, res.Base.Name)
	for i, v := range res.Values {
		if i == 0 {
			fmt.Fprintf(w, ": ")
		} else {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "%v", fmtInt(v))
	}
	fmt.Fprintf(w, "\n")
}

func (c *Call) Serialize(w io.Writer) {
	fmt.Fprintf(w, "%v(", c.Name.Name)
	for i, a := range c.Args {
		if i != 0 {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "%v", fmtField(a))
	}
	fmt.Fprintf(w, ")")
	if c.Ret != nil {
		fmt.Fprintf(w, " %v", fmtType(c.Ret))
	}
	fmt.Fprintf(w, "\n")
}

func (str *Struct) Serialize(w io.Writer) {
	opening, closing := '{', '}'
	if str.IsUnion {
		opening, closing = '[', ']'
	}
	fmt.Fprintf(w, "%v %c\n", str.Name.Name, opening)
	// Align all field types to the same column.
	const tabWidth = 8
	maxTabs := 0
	for _, f := range str.Fields {
		tabs := (len(f.Name.Name) + tabWidth) / tabWidth
		if maxTabs < tabs {
			maxTabs = tabs
		}
	}
	for _, f := range str.Fields {
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
		fmt.Fprintf(w, "%v\n", fmtType(f.Type))
	}
	for _, com := range str.Comments {
		fmt.Fprintf(w, "#%v\n", com.Text)
	}
	fmt.Fprintf(w, "%c", closing)
	if len(str.Attrs) != 0 {
		fmt.Fprintf(w, " [")
		for i, attr := range str.Attrs {
			fmt.Fprintf(w, "%v%v", comma(i), attr.Name)
		}
		fmt.Fprintf(w, "]")
	}
	fmt.Fprintf(w, "\n")
}

func (flags *IntFlags) Serialize(w io.Writer) {
	fmt.Fprintf(w, "%v = ", flags.Name.Name)
	for i, v := range flags.Values {
		if i != 0 {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "%v", fmtInt(v))
	}
	fmt.Fprintf(w, "\n")
}

func (flags *StrFlags) Serialize(w io.Writer) {
	fmt.Fprintf(w, "%v = ", flags.Name.Name)
	for i, v := range flags.Values {
		if i != 0 {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "\"%v\"", v.Value)
	}
	fmt.Fprintf(w, "\n")
}

func fmtField(f *Field) string {
	return fmt.Sprintf("%v %v", f.Name.Name, fmtType(f.Type))
}

func fmtType(t *Type) string {
	v := ""
	switch {
	case t.Ident != "":
		v = t.Ident
	case t.String != "":
		v = fmt.Sprintf("\"%v\"", t.String)
	default:
		v = fmtIntValue(t.Value, t.ValueHex)
	}
	switch {
	case t.Ident2 != "":
		v += fmt.Sprintf(":%v", t.Ident2)
	case t.Value2 != 0:
		v += fmt.Sprintf(":%v", fmtIntValue(t.Value2, t.Value2Hex))
	}
	v += fmtTypeList(t.Args)
	return v
}

func fmtTypeList(args []*Type) string {
	if len(args) == 0 {
		return ""
	}
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "[")
	for i, t := range args {
		fmt.Fprintf(w, "%v%v", comma(i), fmtType(t))
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
		return fmtIntValue(i.Value, i.ValueHex)
	}
}

func fmtIntValue(v uint64, hex bool) string {
	if hex {
		return fmt.Sprintf("0x%x", v)
	}
	return fmt.Sprint(v)
}

func comma(i int) string {
	if i == 0 {
		return ""
	}
	return ", "
}
