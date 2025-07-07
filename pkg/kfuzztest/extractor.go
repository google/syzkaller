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

	// We use an index to avoid repeated sequential scans of the whole binary,
	// as this is by far the most expensive operation. We currently need this
	// index for two things - parsing test cases and parsing constraints. It is
	// likely that it will be used for object types too.
	symbolsIndexInitialized bool
	symbolsIndex            map[string]elf.Symbol
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
	return &Extractor{vmlinuxPath, elfFile, dwarfData, false, make(map[string]elf.Symbol)}, nil
}

func (e *Extractor) ExtractAll() ([]SyzFunc, []SyzStruct, []SyzConstraint, error) {
	funcs, err := e.extractFuncs()
	if err != nil {
		return nil, nil, nil, err
	}
	structs, err := e.extractStructs(funcs)
	if err != nil {
		return nil, nil, nil, err
	}
	constraints, err := e.extractDomainConstraints()
	if err != nil {
		return nil, nil, nil, err
	}
	return funcs, structs, constraints, nil
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

// Reads a string of length at most 128 bytes from the Extractor's elf file
func (e *Extractor) readElfString(offset uint64) string {
	strSection := e.elfSection(offset)
	if strSection == nil {
		fmt.Printf("unable to find section for offset 0x%X\n", offset)
		return ""
	}

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

func (e *Extractor) buildSymbolIndex() error {
	if e.symbolsIndexInitialized {
		return nil
	}

	symbols, err := e.elfFile.Symbols()
	if err != nil {
		return err
	}

	for _, sym := range symbols {
		e.symbolsIndex[sym.Name] = sym
	}

	e.symbolsIndexInitialized = true
	return nil
}

func (e *Extractor) getSymbol(symbolName string) (elf.Symbol, error) {
	if !e.symbolsIndexInitialized {
		err := e.buildSymbolIndex()
		if err != nil {
			return elf.Symbol{}, err
		}
	}

	symbol, contains := e.symbolsIndex[symbolName]
	if !contains {
		return elf.Symbol{}, fmt.Errorf("symbol not found in binary")
	}
	return symbol, nil
}

func (e *Extractor) extractFuncs() ([]SyzFunc, error) {
	var rawFuncs []*kftfTestCase
	var err error

	rawFuncs, err = parseKftfObjects[*kftfTestCase](e)
	if err != nil {
		return nil, err
	}

	fuzzTargets := make([]SyzFunc, len(rawFuncs))
	for i, raw := range rawFuncs {
		fuzzTargets[i] = SyzFunc{
			Name:            e.readElfString(raw.name),
			InputStructName: e.readElfString(raw.argType),
		}
	}

	return fuzzTargets, nil
}

func (e *Extractor) extractDomainConstraints() ([]SyzConstraint, error) {
	var rawConstraints []*kftfConstraint
	var err error

	rawConstraints, err = parseKftfObjects[*kftfConstraint](e)
	if err != nil {
		return nil, err
	}

	constraints := make([]SyzConstraint, len(rawConstraints))
	for i, raw := range rawConstraints {
		constraints[i] = SyzConstraint{
			InputType:      e.readElfString(raw.inputType),
			FieldName:      e.readElfString(raw.fieldName),
			Value1:         raw.value1,
			Value2:         raw.value2,
			ConstraintType: ConstraintType(raw.constraintType),
		}
	}

	return constraints, nil
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

// Parses a slice of kftf objects contained within a dedicated section. This
// function assumes that all entries are tightly packed, and that each section
// contains only one type of statically-sized entry types.
func parseKftfObjects[T interface {
	*P
	parsableFromBytes
}, P any](e *Extractor) ([]T, error) {
	var typeinfo T = new(P)

	startSymbol, err := e.getSymbol(typeinfo.startSymbol())
	if err != nil {
		return nil, err
	} else if startSymbol.Value == 0 {
		return nil, fmt.Errorf("Failed to resolve start symbol")
	}

	endSymbol, err := e.getSymbol(typeinfo.endSymbol())
	if err != nil {
		return nil, err
	} else if endSymbol.Value == 0 {
		return nil, fmt.Errorf("Failed to resolve end symbol")
	}

	out := make([]T, 0)
	data := make([]byte, typeinfo.size())
	for addr := startSymbol.Value; addr < endSymbol.Value; addr += typeinfo.size() {
		section := e.elfSection(addr)
		if section == nil {
			return nil, fmt.Errorf("Failed to locate section for addr=0x%x", addr)
		}

		n, err := section.ReadAt(data, int64(addr-section.Addr))
		if err != nil || n < int(typeinfo.size()) {
			// if n < sizeof(T), then err is non-nil as per the documentation
			// of section.ReadAt
			return nil, err
		}

		var obj T = new(P)
		obj.fromBytes(e.elfFile, data)
		out = append(out, obj)
	}

	return out, nil
}
