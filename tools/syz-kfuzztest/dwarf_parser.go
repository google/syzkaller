package main

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log"
	"strings"
)

// This is the size of a KFuzzTestCase inside of VMlinux
// FIXME: this size should probably be parsed from DWARF as well for
// completeness. This solution is quite brittle.
const kfuzzTestSize uint64 = 32

// Wraps the metadata contained in a kFuzzTestCase
type kFuzzTestCase struct {
	testName string
	argType  string
}

type dwarfParser struct {
	elfFile *elf.File
	file    *dwarf.Data
	edges   map[string][]string
	// ensures that we only visit each individual struct at most once
	visited map[string]*dwarf.StructType
	// maps function name to their input type
	funcs map[string]string
}

func newDwarfParser(vmlinuxPath string) (*dwarfParser, error) {
	elfFile, err := elf.Open(vmlinuxPath)
	if err != nil {
		return nil, err
	}
	dwarfFile, err := elfFile.DWARF()
	if err != nil {
		return nil, err
	}
	return &dwarfParser{
		elfFile: elfFile,
		file:    dwarfFile,
		edges:   make(map[string][]string),
		visited: make(map[string]*dwarf.StructType),
		funcs:   make(map[string]string),
	}, nil
}

func (d *dwarfParser) findSection(addr uint64) *elf.Section {
	for _, section := range d.elfFile.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			return section
		}
	}
	return nil
}

type kftfTestCase struct {
	name    uint64
	argType uint64
	writeCb uint64
	readCb  uint64
}

func (d *dwarfParser) kftfTestCaseFromBytes(data []byte) kftfTestCase {
	return kftfTestCase{
		name:    d.elfFile.ByteOrder.Uint64(data[0:8]),
		argType: d.elfFile.ByteOrder.Uint64(data[8:16]),
		writeCb: d.elfFile.ByteOrder.Uint64(data[16:24]),
		readCb:  d.elfFile.ByteOrder.Uint64(data[24:32]),
	}
}

// Reads a string of size at most 128 bytes from the dwarf parser's associated
// elf file.
func (d *dwarfParser) readElfString(offset uint64) string {
	strSection := d.findSection(offset)

	buffer := make([]byte, 128)
	strSection.ReadAt(buffer, int64(offset-strSection.Addr))

	out := ""
	for _, chr := range buffer {
		if chr == 0 {
			break
		}
		out += string(chr)
	}

	return out
}

// Locates all fuzz targets in the kernel binary and returns them, or returns
// a non-nil error on failure.
func (d *dwarfParser) locateKFuzzTestCases() ([]kFuzzTestCase, error) {
	symbols, err := d.elfFile.Symbols()
	if err != nil {
		return nil, err
	}

	var startAddr, stopAddr uint64
	for _, sym := range symbols {
		if sym.Name == "__kftf_start" {
			startAddr = sym.Value
		}
		if sym.Name == "__kftf_end" {
			stopAddr = sym.Value
		}
	}

	if startAddr == 0 || stopAddr == 0 {
		return nil, fmt.Errorf("Failed to resolve __kftf_start or __kftf_end in vmlinux file")
	}

	// locate and parse all test cases within the .kftf section of the vmlinux
	// binary
	var fuzzTargets []kFuzzTestCase
	for addr := startAddr; addr < stopAddr; addr += kfuzzTestSize {
		section := d.findSection(addr)
		if section == nil {
			return nil, fmt.Errorf("Failed to locate section for addr=0x%x", addr)
		}

		data := make([]byte, kfuzzTestSize)
		n, err := section.ReadAt(data, int64(addr-section.Addr))
		if err != nil || n < int(kfuzzTestSize) {
			// if n < kfuzzTestSize, then err is non-nil as per the
			// documentation of ReadAt
			return nil, err
		}

		testCase := d.kftfTestCaseFromBytes(data)
		nameSection := d.findSection(testCase.name)

		buffer := make([]byte, 128)
		_, err = nameSection.ReadAt(buffer, int64(testCase.name-nameSection.Addr))
		if err != nil {
			return nil, err
		}

		testName := d.readElfString(testCase.name)
		argType := d.readElfString(testCase.argType)
		fuzzTargets = append(fuzzTargets, kFuzzTestCase{testName, argType})
	}

	return fuzzTargets, nil
}

// locateKFuzzInputStructs adds all top-level fuzz target inputs into a map and
// returns it, or a non-nil error on failure.
func (d *dwarfParser) locateKFuzzInputStructs(testCases []kFuzzTestCase) (map[string]*dwarf.StructType, error) {
	typeMap := make(map[string]*dwarf.StructType)

	// add argument types to a map for faster lookup
	argMap := make(map[string]bool)
	for _, tc := range testCases {
		argMap[tc.argType] = true
	}

	dwarfReader := d.file.Reader()
	for {
		entry, err := dwarfReader.Next()
		if err != nil {
			return nil, err
		}

		// EOF
		if entry == nil {
			break
		}

		if entry.Tag != dwarf.TagStructType {
			continue
		}

		// skip over unnamed structures
		nameField := entry.AttrField(dwarf.AttrName)
		if nameField == nil {
			continue
		}

		name, ok := nameField.Val.(string)
		if !ok {
			fmt.Printf("unable to get name field\n")
			continue
		}

		// Dwarf file prefixes structures with `struct` so we must prepend
		// before lookup.
		structName := "struct " + name
		// Check whether or not this type is one that we parsed previously
		// while traversing the .kftf section of the vmlinux binary, discarding
		// if this is not the case.
		if _, ok := argMap[structName]; !ok {
			continue
		}

		t, err := d.dwarfGetType(entry)
		if err != nil {
			return nil, err
		}
		switch entryType := t.(type) {
		case *dwarf.StructType:
			typeMap[structName] = entryType
		default:
			// We shouldn't hit this branch if everything before this is
			// correct.
			panic("Error parsing dwarf - well-formed?")
		}
	}

	return typeMap, nil
}

func (d *dwarfParser) String() string {
	out := ""
	for a, bs := range d.edges {
		out += fmt.Sprintf("%s\n", a)
		for _, b := range bs {
			out += fmt.Sprintf("\t%s\n", b)
		}
	}

	return out
}

func (d *dwarfParser) dumpDagRecur(indent string, node string) {
	fmt.Printf("%s%s\n", indent, node)
	for _, nextNode := range d.edges[node] {
		d.dumpDagRecur(indent+"  ", nextNode)
	}
}

//nolint:all
func (d *dwarfParser) dumpDag() {
	fmt.Printf("dumping DAG...\n")
	for node := range d.edges {
		d.dumpDagRecur("", node)
		fmt.Printf("\n\n") // separator
	}
}

func (d *dwarfParser) addFunc(funcName, argType string) {
	d.funcs[funcName] = argType
}

func (d *dwarfParser) dwarfGetType(entry *dwarf.Entry) (dwarf.Type, error) {
	// Case 1: The entry is itself a type definition (e.g., TagStructType, TagBaseType).
	// We use its own offset to get the dwarf.Type object.
	switch entry.Tag {
	case dwarf.TagStructType, dwarf.TagBaseType, dwarf.TagTypedef, dwarf.TagPointerType, dwarf.TagArrayType:
		return d.file.Type(entry.Offset)
	}

	// Case 2: The entry refers to a type (e.g., TagMember, TagVariable).
	// We use its AttrType field to find the offset of the type definition.
	typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, fmt.Errorf("entry (Tag: %s) has no AttrType field", entry.Tag)
	}

	return d.file.Type(typeOffset)
}

// Perform a DFS from a start struct to form a DAG Of structs that we can then
// topologically sort it and get a list of structs to generate.
func (d *dwarfParser) dwarfBuildStructDag(start *dwarf.StructType) error {
	d.visited[start.StructName] = start
	for _, child := range start.Field {
		switch childType := child.Type.(type) {
		case *dwarf.StructType:
			if _, contains := d.visited[childType.StructName]; !contains {
				d.visited[childType.StructName] = childType
				// recusively call, generating the relevant DAG entry
				d.dwarfBuildStructDag(childType)
			}
			d.edges[start.StructName] = append(d.edges[start.StructName], childType.StructName)
		}
	}
	return nil
}

// topologically sorts the DAG that is generated from a dwarf file
func (d *dwarfParser) topologicalSortDag() []string {
	// output
	sorted := []string{}
	visited := make(map[string]bool)

	// contains all nodes that we visited during DAG construction
	startNodes := make(map[string]bool)
	for node := range d.visited {
		startNodes[node] = true
	}

	// remove all nodes that can't be a start node as they have an incoming
	// edge
	for _, nodes := range d.edges {
		for _, node := range nodes {
			if startNodes[node] {
				delete(startNodes, node)
			}
		}
	}

	// recusive DFS visitor function
	var visit func(string)
	visit = func(node string) {
		// prepend
		sorted = append([]string{node}, sorted...)

		for _, child := range d.edges[node] {
			if _, ok := visited[child]; !ok {
				visited[child] = true
				visit(child)
			}
		}
	}

	// range over the structs that we visited before...
	for node := range startNodes {
		if !visited[node] {
			visit(node)
		}
	}

	return sorted
}

func syzlangDescriptionStruct(s *dwarf.StructType) string {
	out := fmt.Sprintf("%s {\n", s.StructName)
	for _, field := range s.Field {
		typeName := dwarfToSyzlangType(field.Type.String())
		out += fmt.Sprintf("\t%s\t%s\n", field.Name, typeName)
	}
	out += "}"
	return out
}

func syzlangDescriptionFunc(funcName, argType string) string {
	argType = strings.TrimPrefix(argType, "struct ")

	out := fmt.Sprintf("syz_kfuzztest_run$%s(", funcName)
	out += fmt.Sprintf("name ptr[in, string[\"%s\"]], ", funcName)
	out += fmt.Sprintf("data ptr[in, %s], ", argType)
	out += "len bytesize[data])"

	return out
}

// syzlangDescription generates the syzlang description of a given set of
// struct definitions
func (d *dwarfParser) syzlangDescription() string {
	out := "# This description was automagically generated by syz-kfuzztest.\n"

	sortedNodes := d.topologicalSortDag()
	for _, node := range sortedNodes {
		structType, ok := d.visited[node]
		if !ok {
			log.Fatalf("tried to create description for an unknown struct")
		}

		out += syzlangDescriptionStruct(structType)
		out += "\n\n" // separator
	}

	// add pseudo-syscalls
	for funcName, argType := range d.funcs {
		out += syzlangDescriptionFunc(funcName, argType)
		out += "\n"
	}

	return out
}

func dwarfToSyzlangType(typeName string) string {
	if after, ok := strings.CutPrefix(typeName, "struct "); ok {
		return after
	}

	switch typeName {
	case "long unsigned int":
		return "int64"
	case "int":
		return "int32"
	case "char":
		return "int8"
	default:
		return typeName
	}
}
