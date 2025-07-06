package kfuzztest

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
)

// Extractor's job is to extract all information relevant to the KFuzzTest
// framework from a VMlinux binary
type Extractor struct {
	// Path to the `vmlinux` being parsed
	vmlinuxPath string
	elfFile     *elf.File
	dwarfData   *dwarf.Data
}

type kftfTestCase struct {
	name    uint64
	argType uint64
	writeCb uint64
	readCb  uint64
}

func NewExtractor(vmlinuxPath string) (*Extractor, error) {
	elfFile, err := elf.Open(vmlinuxPath)
	if err != nil {
		return nil, err
	}
	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return nil, err
	}
	return &Extractor{vmlinuxPath, elfFile, dwarfData}, nil
}

func (e *Extractor) ExtractAll() ([]SyzFunc, []SyzStruct, error) {
	funcs, err := e.extractFuncs()
	if err != nil {
		return nil, nil, err
	}
	structs, err := e.extractStructs(funcs)
	if err != nil {
		return nil, nil, err
	}

	return funcs, structs, nil
}

func (e *Extractor) Close() {
	e.elfFile.Close()
}

// given an address, returns the elf section that this address belongs to in
// the Extractor's elf file.
func (e *Extractor) elfSection(addr uint64) *elf.Section {
	for _, section := range e.elfFile.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			return section
		}
	}
	return nil
}

func (e *Extractor) kftfTestCaseFromBytes(data []byte) kftfTestCase {
	return kftfTestCase{
		name:    e.elfFile.ByteOrder.Uint64(data[0:8]),
		argType: e.elfFile.ByteOrder.Uint64(data[8:16]),
		writeCb: e.elfFile.ByteOrder.Uint64(data[16:24]),
		readCb:  e.elfFile.ByteOrder.Uint64(data[24:32]),
	}
}

// Reads a string of length at most 128 bytes from the Extractor's elf file
func (e *Extractor) readElfString(offset uint64) string {
	strSection := e.elfSection(offset)

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

const kftfSectionStart string = "__kftf_start"
const kftfSectionEnd string = "__kftf_end"
const kfuzzTestSize uint64 = 32

func (e *Extractor) extractFuncs() ([]SyzFunc, error) {
	symbols, err := e.elfFile.Symbols()
	if err != nil {
		return nil, err
	}

	var startAddr, stopAddr uint64
	for _, sym := range symbols {
		if sym.Name == kftfSectionStart {
			startAddr = sym.Value
		}
		if sym.Name == kftfSectionEnd {
			stopAddr = sym.Value
		}
	}

	if startAddr == 0 || stopAddr == 0 {
		return nil, fmt.Errorf("Failed to resolve KFTF section in vmlinux file")
	}

	fuzzTargets := make([]SyzFunc, 0)
	for addr := startAddr; addr < stopAddr; addr += kfuzzTestSize {
		section := e.elfSection(addr)
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

		testCase := e.kftfTestCaseFromBytes(data)
		nameSection := e.elfSection(testCase.name)

		buffer := make([]byte, 128)
		_, err = nameSection.ReadAt(buffer, int64(testCase.name-nameSection.Addr))
		if err != nil {
			return nil, err
		}

		testName := e.readElfString(testCase.name)
		argType := e.readElfString(testCase.argType)
		fuzzTargets = append(fuzzTargets, SyzFunc{Name: testName, InputStructName: argType})
	}

	return fuzzTargets, nil
}

func (e *Extractor) dwarfGetType(entry *dwarf.Entry) (dwarf.Type, error) {
	// Case 1: The entry is itself a type definition (e.g., TagStructType, TagBaseType).
	// We use its own offset to get the dwarf.Type object.
	switch entry.Tag {
	case dwarf.TagStructType, dwarf.TagBaseType, dwarf.TagTypedef, dwarf.TagPointerType, dwarf.TagArrayType:
		return e.dwarfData.Type(entry.Offset)
	}

	// Case 2: The entry refers to a type (e.g., TagMember, TagVariable).
	// We use its AttrType field to find the offset of the type definition.
	typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, fmt.Errorf("entry (Tag: %s) has no AttrType field", entry.Tag)
	}

	return e.dwarfData.Type(typeOffset)
}

func (e *Extractor) extractStructs(funcs []SyzFunc) ([]SyzStruct, error) {
	// set of input map names so that we can skip over entries that aren't
	// interesting
	inputStructs := make(map[string]bool)
	for _, fn := range funcs {
		inputStructs[fn.InputStructName] = true
	}

	structs := make([]SyzStruct, 0)

	// perform a DFS on discovered struct types in order to discover nested
	// struct types that may be contained within them
	var visitRecur func(*dwarf.StructType, *map[string]bool)
	visited := make(map[string]bool)
	visitRecur = func(start *dwarf.StructType, visited *map[string]bool) {
		newStruct := SyzStruct{Name: start.StructName, Fields: make([]SyzField, 0)}
		for _, child := range start.Field {
			newField := SyzField{Name: child.Name, TypeName: child.Type.String()}
			newStruct.Fields = append(newStruct.Fields, newField)
			switch childType := child.Type.(type) {
			case *dwarf.StructType:
				if _, contains := (*visited)[childType.StructName]; !contains {
					(*visited)[childType.StructName] = true
					visitRecur(childType, visited)
				}
			default:
				continue
			}
		}
		structs = append(structs, newStruct)
	}

	dwarfReader := e.dwarfData.Reader()
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
		if _, ok := inputStructs[structName]; !ok {
			continue
		}

		t, err := e.dwarfGetType(entry)
		if err != nil {
			return nil, err
		}

		switch entryType := t.(type) {
		case *dwarf.StructType:
			visitRecur(entryType, &visited)
		default:
			// We shouldn't hit this branch if everything before this is
			// correct.
			panic("Error parsing dwarf - well-formed?")
		}
	}

	return structs, nil
}
