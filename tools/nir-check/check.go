package main

import (
	"bytes"
	"flag"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type Warn struct {
	pos  ast.Pos
	arch string
	typ  string
	msg  string
}

type STR struct {
	name   string
	fields map[string]*string
}

const (
	WarnCompiler           = "compiler"
	WarnNoSuchStruct       = "no-such-struct"
	WarnBadStructSize      = "bad-struct-size"
	WarnBadFieldNumber     = "bad-field-number"
	WarnBadFieldSize       = "bad-field-size"
	WarnBadFieldOffset     = "bad-field-offset"
	WarnBadBitfield        = "bad-bitfield"
	WarnNoNetlinkPolicy    = "no-such-netlink-policy"
	WarnNetlinkBadSize     = "bad-kernel-netlink-policy-size"
	WarnNetlinkBadAttrType = "bad-netlink-attr-type"
	WarnNetlinkBadAttr     = "bad-netlink-attr"
)

func main() {

	// locs := getStructs()

	generator()

}

func getStructs() map[string]*ast.Struct {
	// file, err = filepath.Glob("./test/syz_test.txt")

	// if err != nil || file
	var flagOS = flag.String("os", runtime.GOOS, "OS")

	var arch = "amd64"
	structTypes, locs, warnings, err := parseDescriptions_custom("syz_awesome_func.txt", *flagOS, arch)

	if err != nil {
		fmt.Errorf("Error: %v", err)
	}

	fmt.Println(structTypes, locs, warnings)

	//locs map of structs name: adr

	//structs declared in pkg/ast/ast.go

	// type Field struct {
	// 	Pos      Pos
	// 	Name     *Ident
	// 	Type     *Type
	// 	Attrs    []*Type
	// 	NewBlock bool // separated from previous fields by a new line
	// 	Comments []*Comment
	// }

	// type Type struct {
	// 	Pos Pos
	// 	// Only one of Value, Ident, String, Expression is filled.
	// 	Value      uint64
	// 	ValueFmt   IntFmt
	// 	Ident      string
	// 	String     string
	// 	StringFmt  StrFmt
	// 	HasString  bool
	// 	Expression *BinaryExpression
	// 	// Parts after COLON (for ranges and bitfields).
	// 	Colon []*Type
	// 	// Sub-types in [].
	// 	Args []*Type
	// }

	fmt.Print("Printing locs: \n")

	for _, str := range locs {
		fmt.Printf("struct: %v\n", str.Name.Name)
		for i, field := range str.Fields {
			fmt.Println(i, ": ", field.Name.Name, ": ", field.Type.Ident)
		}
		fmt.Println()
	}

	return locs
}

func parseDescriptions_custom(name, OS, arch string) ([]prog.Type, map[string]*ast.Struct, []Warn, error) {
	errorBuf := new(bytes.Buffer)
	var warnings []Warn

	eh := func(pos ast.Pos, msg string) {
		warnings = append(warnings, Warn{pos: pos, typ: WarnCompiler, msg: msg})
		fmt.Fprintf(errorBuf, "%v: %v\n", pos, msg)
	}

	top := ast.ParseGlob(filepath.Join("../../sys", OS, name), eh)

	fmt.Printf("top: %v \n", top)
	if top == nil {
		fmt.Printf("failed to parse txt files:\n%s", errorBuf.Bytes())
		return nil, nil, nil, fmt.Errorf("failed to parse txt files:\n%s", errorBuf.Bytes())
	}

	consts := compiler.DeserializeConstFile(filepath.Join("../../sys", OS, "*.const"), eh).Arch(arch)
	//fmt.Printf("consts: %v", consts)
	if consts == nil {
		fmt.Printf("failed to parse const files:\n%s", errorBuf.Bytes())
		return nil, nil, nil, fmt.Errorf("failed to parse const files:\n%s", errorBuf.Bytes())
	}

	prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
	if prg == nil {
		fmt.Printf("failed to compile descriptions:\n%s", errorBuf.Bytes())
		return nil, nil, nil, fmt.Errorf("failed to compile descriptions:\n%s", errorBuf.Bytes())
	}
	fmt.Printf("prg: %v", prg)

	prog.RestoreLinks(prg.Syscalls, prg.Resources, prg.Types)
	locs := make(map[string]*ast.Struct)
	for _, decl := range top.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			locs[n.Name.Name] = n
		case *ast.TypeDef:
			if n.Struct != nil {
				locs[n.Name.Name] = n.Struct
			}
		}
	}
	var structs []prog.Type
	for _, typ := range prg.Types {
		switch typ.(type) {
		case *prog.StructType, *prog.UnionType:
			structs = append(structs, typ)
		}
	}
	return structs, locs, warnings, nil

	// return nil, nil, nil, nil

}

// func parseDesc () {
//   var filename = "./test/syz_test.txt"
//   fmt.Println(filename)

//   data, err := os.ReadFile(filename)

//   if err != nil {
//     fmt.Println("Err reading file: %v", err)
//   }

//   eh := func(pos ast.Pos, msg string) {
//     fmt.Println("%v: %v", pos, err)
//   }

//   tree := ast.Parse(data, filename, eh)

//   tokens := ast.Format(tree)

//   for _, token := range tokens {
//     fmt.Printf("%c ", token)
//   }

//   fmt.Println(ast.Format(tree))

//   errorBuf := new(bytes.Buffer)

//   OS = "linux"
//   consts := compiler.DeserializeConstFile(filepath.Join("sys", OS, "*.const"), eh).Arch(arch)
// 	if consts == nil {
// 		fmt.Errorf("failed to parse const files:\n%s", errorBuf.Bytes())
// 	}

//   prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
// 	if prg == nil {
// 		fmt.Errorf("failed to compile descriptions:\n%s", errorBuf.Bytes())
// 	}
// }

func parseDescriptions(OS, arch string) ([]prog.Type, map[string]*ast.Struct, []Warn, error) {
	errorBuf := new(bytes.Buffer)
	var warnings []Warn

	eh := func(pos ast.Pos, msg string) {
		warnings = append(warnings, Warn{pos: pos, typ: WarnCompiler, msg: msg})
		fmt.Fprintf(errorBuf, "%v: %v\n", pos, msg)
	}

	top := ast.ParseGlob(filepath.Join("../../sys", OS, "*.txt"), eh)
	fmt.Printf("top: %v", top)
	if top == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse txt files:\n%s", errorBuf.Bytes())
	}

	consts := compiler.DeserializeConstFile(filepath.Join("sys", OS, "*.const"), eh).Arch(arch)
	if consts == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse const files:\n%s", errorBuf.Bytes())
	}
	prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
	if prg == nil {
		return nil, nil, nil, fmt.Errorf("failed to compile descriptions:\n%s", errorBuf.Bytes())
	}
	prog.RestoreLinks(prg.Syscalls, prg.Resources, prg.Types)
	locs := make(map[string]*ast.Struct)
	for _, decl := range top.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			locs[n.Name.Name] = n
		case *ast.TypeDef:
			if n.Struct != nil {
				locs[n.Name.Name] = n.Struct
			}
		}
	}
	var structs []prog.Type
	for _, typ := range prg.Types {
		switch typ.(type) {
		case *prog.StructType, *prog.UnionType:
			structs = append(structs, typ)
		}
	}
	return structs, locs, warnings, nil
}

/*
Получается большую часть времени - реализация
Но аналитику тоже пишу:
Конкретно актуальность новизна лалала
И описание методов различных, которые можно использовать для проверки
*/
