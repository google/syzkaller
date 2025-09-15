// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"
)

// Extractor's job is to extract all information relevant to KFuzzTest from a
// VMlinux binary.
type Extractor struct {
	// Path to the `vmlinux` being parsed.
	vmlinuxPath string
	elfFile     *elf.File
	dwarfData   *dwarf.Data

	// We use an index to avoid repeated sequential scans of the whole binary,
	// as this is by far the most expensive operation.
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
		elfFile.Close()
		return nil, err
	}
	return &Extractor{vmlinuxPath, elfFile, dwarfData, false, make(map[string]elf.Symbol)}, nil
}

type ExtractAllResult struct {
	VMLinuxPath string
	Funcs       []SyzFunc
	Structs     []SyzStruct
	Constraints []SyzConstraint
	Annotations []SyzAnnotation
}

func (e *Extractor) ExtractAll() (ExtractAllResult, error) {
	funcs, err := e.extractFuncs()
	if err != nil {
		return ExtractAllResult{}, err
	}
	structs, err := e.extractStructs(funcs)
	if err != nil {
		return ExtractAllResult{}, err
	}
	constraints, err := e.extractDomainConstraints()
	if err != nil {
		return ExtractAllResult{}, err
	}
	annotations, err := e.extractAnnotations()
	if err != nil {
		return ExtractAllResult{}, err
	}

	if len(structs) < len(funcs) {
		return ExtractAllResult{}, fmt.Errorf("inconsistent KFuzzTest metadata found in vmlinux")
	}
	if len(funcs) == 0 {
		return ExtractAllResult{}, nil
	}

	return ExtractAllResult{
		VMLinuxPath: e.vmlinuxPath,
		Funcs:       funcs,
		Structs:     structs,
		Constraints: constraints,
		Annotations: annotations,
	}, nil
}

func (e *Extractor) Close() {
	e.elfFile.Close()
}

func (e *ExtractAllResult) String() string {
	var builder strings.Builder

	fmt.Fprint(&builder, "extraction result:\n")
	fmt.Fprintf(&builder, "\tVMLinux image:   %s\n", e.VMLinuxPath)
	fmt.Fprintf(&builder, "\tnum targets:     %d\n", len(e.Funcs))
	fmt.Fprintf(&builder, "\tnum struct:      %d\n", len(e.Structs))
	fmt.Fprintf(&builder, "\tnum constraints: %d\n", len(e.Constraints))
	fmt.Fprintf(&builder, "\tnum annotations: %d\n", len(e.Annotations))

	return builder.String()
}

// Given an address, returns the elf section that this address belongs to in
// the Extractor's elf file.
func (e *Extractor) elfSection(addr uint64) *elf.Section {
	for _, section := range e.elfFile.Sections {
		if addr >= section.Addr && addr < section.Addr+section.Size {
			return section
		}
	}
	return nil
}

// Reads a string of length at most 128 bytes from the Extractor's elf file.
func (e *Extractor) readElfString(offset uint64) (string, error) {
	strSection := e.elfSection(offset)
	if strSection == nil {
		return "", fmt.Errorf("unable to find section for offset 0x%X", offset)
	}

	// 128 bytes is longer than we expect to see in KFuzzTest metadata.
	buffer := make([]byte, 128)
	_, err := strSection.ReadAt(buffer, int64(offset-strSection.Addr))
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	for _, chr := range buffer {
		if chr == 0 {
			return builder.String(), nil
		}
		builder.WriteByte(chr)
	}

	return "", fmt.Errorf("could not find null-terminated string with length < 128")
}

func (e *Extractor) buildSymbolIndex() error {
	symbols, err := e.elfFile.Symbols()
	if err != nil {
		return err
	}
	for _, sym := range symbols {
		e.symbolsIndex[sym.Name] = sym
	}
	return nil
}

func (e *Extractor) getSymbol(symbolName string) (elf.Symbol, error) {
	if !e.symbolsIndexInitialized {
		err := e.buildSymbolIndex()
		e.symbolsIndexInitialized = true
		if err != nil {
			return elf.Symbol{}, err
		}
	}

	symbol, contains := e.symbolsIndex[symbolName]
	if !contains {
		return elf.Symbol{}, fmt.Errorf("symbol %s not found in %s", symbolName, e.vmlinuxPath)
	}
	return symbol, nil
}

func (e *Extractor) extractFuncs() ([]SyzFunc, error) {
	var rawFuncs []*kfuzztestTarget
	var err error

	rawFuncs, err = parseKftfObjects[*kfuzztestTarget](e)
	if err != nil {
		return nil, err
	}

	fuzzTargets := make([]SyzFunc, len(rawFuncs))
	for i, raw := range rawFuncs {
		name, err := e.readElfString(raw.name)
		if err != nil {
			return []SyzFunc{}, err
		}
		argType, err := e.readElfString(raw.argType)
		if err != nil {
			return []SyzFunc{}, err
		}
		fuzzTargets[i] = SyzFunc{
			Name:            name,
			InputStructName: argType,
		}
	}

	return fuzzTargets, nil
}

func (e *Extractor) extractDomainConstraints() ([]SyzConstraint, error) {
	var rawConstraints []*kfuzztestConstraint
	var err error

	rawConstraints, err = parseKftfObjects[*kfuzztestConstraint](e)
	if err != nil {
		return nil, err
	}

	constraints := make([]SyzConstraint, len(rawConstraints))
	for i, raw := range rawConstraints {
		typeName, err := e.readElfString(raw.inputType)
		if err != nil {
			return []SyzConstraint{}, err
		}
		fieldName, err := e.readElfString(raw.fieldName)
		if err != nil {
			return []SyzConstraint{}, err
		}

		constraints[i] = SyzConstraint{
			InputType:      typeName,
			FieldName:      fieldName,
			Value1:         raw.value1,
			Value2:         raw.value2,
			ConstraintType: ConstraintType(raw.constraintType),
		}
	}

	return constraints, nil
}

func (e *Extractor) extractAnnotations() ([]SyzAnnotation, error) {
	var rawAnnotations []*kfuzztestAnnotation
	var err error

	rawAnnotations, err = parseKftfObjects[*kfuzztestAnnotation](e)
	if err != nil {
		return nil, err
	}

	annotations := make([]SyzAnnotation, len(rawAnnotations))
	for i, raw := range rawAnnotations {
		typeName, err := e.readElfString(raw.inputType)
		if err != nil {
			return nil, err
		}
		fieldName, err := e.readElfString(raw.fieldName)
		if err != nil {
			return nil, err
		}
		linkedFieldName, err := e.readElfString(raw.linkedFieldName)
		if err != nil {
			return nil, err
		}

		annotations[i] = SyzAnnotation{
			InputType:       typeName,
			FieldName:       fieldName,
			LinkedFieldName: linkedFieldName,
			Attribute:       AnnotationAttribute(raw.annotationAttribute),
		}
	}

	return annotations, nil
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

// extractStructs extracts input structure metadata from discovered KFuzzTest
// targets (funcs).
// Performs a tree-traversal as all struct types need to be defined in the
// resulting description that is emitted by the builder.
func (e *Extractor) extractStructs(funcs []SyzFunc) ([]SyzStruct, error) {
	// Set of input map names so that we can skip over entries that aren't
	// interesting.
	inputStructs := make(map[string]bool)
	for _, fn := range funcs {
		inputStructs[fn.InputStructName] = true
	}
	// Unpacks nested types to find an underlying struct type, or return nil
	// if nothing is found. For example, when called on `struct myStruct **`
	// we return `struct myStruct`.
	unpackNested := func(t dwarf.Type) *dwarf.StructType {
		for {
			switch concreteType := t.(type) {
			case *dwarf.StructType:
				return concreteType
			case *dwarf.PtrType:
				t = concreteType.Type
			case *dwarf.QualType:
				t = concreteType.Type
			default:
				return nil
			}
		}
	}

	structs := make([]SyzStruct, 0)

	// Perform a DFS on discovered struct types in order to discover nested
	// struct types that may be contained within them.
	visited := make(map[string]bool)
	var visitRecur func(*dwarf.StructType)
	visitRecur = func(start *dwarf.StructType) {
		newStruct := SyzStruct{dwarfType: start, Name: start.StructName, Fields: make([]SyzField, 0)}
		for _, child := range start.Field {
			newField := SyzField{Name: child.Name, dwarfType: child.Type}
			newStruct.Fields = append(newStruct.Fields, newField)
			switch childType := child.Type.(type) {
			case *dwarf.StructType:
				if _, contains := visited[childType.StructName]; !contains {
					visited[childType.StructName] = true
					visitRecur(childType)
				}
			case *dwarf.PtrType, *dwarf.QualType:
				// If we hit a pointer or a qualifier, we unpack to see if we
				// find a nested struct type so that we can visit it.
				maybeStructType := unpackNested(childType)
				if maybeStructType != nil {
					if _, contains := visited[maybeStructType.StructName]; !contains {
						visited[maybeStructType.StructName] = true
						visitRecur(maybeStructType)
					}
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
		// EOF.
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		// Skip over unnamed structures.
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
			visitRecur(entryType)
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
	var typeinfo T

	startSymbol, err := e.getSymbol(typeinfo.startSymbol())
	if err != nil {
		return nil, err
	} else if startSymbol.Value == 0 {
		return nil, fmt.Errorf("failed to resolve %s", typeinfo.startSymbol())
	}

	endSymbol, err := e.getSymbol(typeinfo.endSymbol())
	if err != nil {
		return nil, err
	} else if endSymbol.Value == 0 {
		return nil, fmt.Errorf("failed to resolve %s", typeinfo.endSymbol())
	}

	out := make([]T, 0)
	data := make([]byte, typeinfo.size())
	for addr := startSymbol.Value; addr < endSymbol.Value; addr += typeinfo.size() {
		section := e.elfSection(addr)
		if section == nil {
			return nil, fmt.Errorf("failed to locate section for addr=0x%x", addr)
		}

		n, err := section.ReadAt(data, int64(addr-section.Addr))
		if err != nil || n < int(typeinfo.size()) {
			// If n < sizeof(T), then err is non-nil as per the documentation
			// of section.ReadAt.
			return nil, err
		}

		obj := T(new(P))
		err = obj.fromBytes(e.elfFile, data)
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}

	return out, nil
}
