// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
)

type Builder struct {
	funcs       []SyzFunc
	structs     []SyzStruct
	constraints []SyzConstraint
	annotations []SyzAnnotation
}

func NewBuilder(
	funcs []SyzFunc,
	structs []SyzStruct,
	constraints []SyzConstraint,
	annotations []SyzAnnotation,
) *Builder {
	return &Builder{funcs, structs, constraints, annotations}
}

func (b *Builder) AddStruct(s SyzStruct) {
	b.structs = append(b.structs, s)
}

func (b *Builder) AddFunc(f SyzFunc) {
	b.funcs = append(b.funcs, f)
}

func (b *Builder) EmitSyzlangDescription() (string, error) {
	constraintMap := make(map[string]map[string]SyzConstraint)
	for _, constraint := range b.constraints {
		if _, contains := constraintMap[constraint.InputType]; !contains {
			constraintMap[constraint.InputType] = make(map[string]SyzConstraint)
		}
		constraintMap[constraint.InputType][constraint.FieldName] = constraint
	}
	annotationMap := make(map[string]map[string]SyzAnnotation)
	for _, annotation := range b.annotations {
		if _, contains := annotationMap[annotation.InputType]; !contains {
			annotationMap[annotation.InputType] = make(map[string]SyzAnnotation)
		}
		annotationMap[annotation.InputType][annotation.FieldName] = annotation
	}

	var descBuilder strings.Builder
	descBuilder.WriteString("# This description was automatically generated with tools/kfuzztest-gen\n")
	for _, s := range b.structs {
		structDesc, err := syzStructToSyzlang(s, constraintMap, annotationMap)
		if err != nil {
			return "", err
		}
		descBuilder.WriteString(structDesc)
		descBuilder.WriteString("\n\n")
	}

	for i, fn := range b.funcs {
		descBuilder.WriteString(syzFuncToSyzlang(fn))
		if i < len(b.funcs)-1 {
			descBuilder.WriteString("\n")
		}
	}

	// Format the output syzlang descriptions for consistency.
	var astError error
	eh := func(pos ast.Pos, msg string) {
		astError = fmt.Errorf("ast failure: %v: %v", pos, msg)
	}
	descAst := ast.Parse([]byte(descBuilder.String()), "", eh)
	if astError != nil {
		return "", astError
	}
	if descAst == nil {
		return "", fmt.Errorf("failed to format generated syzkaller description - is it well-formed?")
	}
	return string(ast.Format(descAst)), nil
}

func syzStructToSyzlang(s SyzStruct, constraintMap map[string]map[string]SyzConstraint,
	annotationMap map[string]map[string]SyzAnnotation) (string, error) {
	var builder strings.Builder

	fmt.Fprintf(&builder, "%s {\n", s.Name)
	structAnnotations := annotationMap["struct "+s.Name]
	structConstraints := constraintMap["struct "+s.Name]
	for _, field := range s.Fields {
		line, err := syzFieldToSyzLang(field, structConstraints, structAnnotations)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&builder, "\t%s\n", line)
	}
	fmt.Fprint(&builder, "}")
	return builder.String(), nil
}

func syzFieldToSyzLang(field SyzField, constraintMap map[string]SyzConstraint,
	annotationMap map[string]SyzAnnotation) (string, error) {
	constraint, hasConstraint := constraintMap[field.Name]
	annotation, hasAnnotation := annotationMap[field.Name]

	var typeDesc string
	var err error
	if hasAnnotation {
		// Annotations override the existing type definitions.
		typeDesc, err = processAnnotation(field, annotation)
	} else {
		typeDesc, err = dwarfToSyzlangType(field.dwarfType)
	}
	if err != nil {
		return "", err
	}

	// Process constraints only if unannotated.
	// TODO: is there a situation where we would want to process both?
	if hasConstraint && !hasAnnotation {
		constraint, err := processConstraint(constraint)
		if err != nil {
			return "", err
		}
		typeDesc += constraint
	}
	return fmt.Sprintf("%s %s", field.Name, typeDesc), nil
}

func processConstraint(c SyzConstraint) (string, error) {
	switch c.ConstraintType {
	case ExpectEq:
		return fmt.Sprintf("[%d]", c.Value1), nil
	case ExpectNe:
		// syzkaller does not have a built-in way to support an inequality
		// constraint AFAIK.
		return "", nil
	case ExpectLt:
		return fmt.Sprintf("[0:%d]", c.Value1-1), nil
	case ExpectLe:
		return fmt.Sprintf("[0:%d]", c.Value1), nil
	case ExpectGt:
		return fmt.Sprintf("[%d]", c.Value1+1), nil
	case ExpectGe:
		return fmt.Sprintf("[%d]", c.Value1), nil
	case ExpectInRange:
		return fmt.Sprintf("[%d:%d]", c.Value1, c.Value2), nil
	default:
		fmt.Printf("c = %d\n", c.ConstraintType)
		return "", fmt.Errorf("unsupported constraint type")
	}
}

func processAnnotation(field SyzField, annotation SyzAnnotation) (string, error) {
	switch annotation.Attribute {
	case AttributeLen:
		underlyingType, err := dwarfToSyzlangType(field.dwarfType)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("len[%s, %s]", annotation.LinkedFieldName, underlyingType), nil
	case AttributeString:
		return "ptr[in, string]", nil
	case AttributeArray:
		pointeeType, isPtr := resolvesToPtr(field.dwarfType)
		if !isPtr {
			return "", fmt.Errorf("can only annotate pointer fields are arrays")
		}
		// TODO: discards const qualifier.
		typeDesc, err := dwarfToSyzlangType(pointeeType)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ptr[in, array[%s]]", typeDesc), nil
	default:
		return "", fmt.Errorf("unsupported attribute type")
	}
}

// Returns true iff `dwarfType` resolved down to a pointer. For example,
// a `const *void` which isn't directly a pointer.
func resolvesToPtr(dwarfType dwarf.Type) (dwarf.Type, bool) {
	switch t := dwarfType.(type) {
	case *dwarf.QualType:
		return resolvesToPtr(t.Type)
	case *dwarf.PtrType:
		return t.Type, true
	}
	return nil, false
}

func syzFuncToSyzlang(s SyzFunc) string {
	var builder strings.Builder
	typeName := strings.TrimPrefix(s.InputStructName, "struct ")

	fmt.Fprintf(&builder, "syz_kfuzztest_run$%s(", s.Name)
	fmt.Fprintf(&builder, "name ptr[in, string[\"%s\"]], ", s.Name)
	fmt.Fprintf(&builder, "data ptr[in, %s], ", typeName)
	builder.WriteString("len bytesize[data], ")
	builder.WriteString("buf ptr[in, array[int8, 65536]]) ")
	// TODO:(ethangraham) The only other way I can think of getting this name
	// would involve using the "reflect" package and matching against the
	// KFuzzTest name, which isn't much better than hardcoding this.
	builder.WriteString("(kfuzz_test)")
	return builder.String()
}

// Given a dwarf type, returns a syzlang string representation of this type.
func dwarfToSyzlangType(dwarfType dwarf.Type) (string, error) {
	switch t := dwarfType.(type) {
	case *dwarf.PtrType:
		underlyingType, err := dwarfToSyzlangType(t.Type)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ptr[in, %s]", underlyingType), nil
	case *dwarf.QualType:
		if t.Qual == "const" {
			return dwarfToSyzlangType(t.Type)
		} else {
			return "", fmt.Errorf("no support for %s qualifier", t.Qual)
		}
	case *dwarf.ArrayType:
		underlyingType, err := dwarfToSyzlangType(t.Type)
		if err != nil {
			return "", err
		}
		// If t.Count == -1 then this is a varlen array as per debug/dwarf
		// documentation.
		if t.Count == -1 {
			return fmt.Sprintf("array[%s]", underlyingType), nil
		} else {
			return fmt.Sprintf("array[%s, %d]", underlyingType, t.Count), nil
		}
	case *dwarf.TypedefType:
		return dwarfToSyzlangType(t.Type)
	case *dwarf.IntType, *dwarf.UintType:
		numBits := t.Size() * 8
		return fmt.Sprintf("int%d", numBits), nil
	case *dwarf.CharType, *dwarf.UcharType:
		return "int8", nil
	// `void` isn't a valid type by itself, so we know that it would have
	// been wrapped in a pointer, e.g., `void *`. For this reason, we can return
	// just interpret it as a byte, i.e., int8.
	case *dwarf.VoidType:
		return "int8", nil
	case *dwarf.StructType:
		return strings.TrimPrefix(t.StructName, "struct "), nil
	default:
		return "", fmt.Errorf("unsupported type %s", dwarfType.String())
	}
}
