// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"fmt"
	"regexp"
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
		descBuilder.WriteString(syzStructToSyzlang(s, constraintMap, annotationMap))
		descBuilder.WriteString("\n\n")
	}

	for i, fn := range b.funcs {
		descBuilder.WriteString(syzFuncToSyzlang(fn))
		if i < len(b.funcs)-1 {
			descBuilder.WriteString("\n")
		}
	}

	fmt.Println(descBuilder.String())

	// Format the output syzlang descriptions.
	var astError error
	eh := func(pos ast.Pos, msg string) {
		astError = fmt.Errorf("Failure: %v: %v\n", pos, msg)
	}
	descAst := ast.Parse([]byte(descBuilder.String()), "", eh)
	if astError != nil {
		return "", astError
	}
	if descAst == nil {
		return "", fmt.Errorf("Failed to format generated syzlang. Is it well-formed?")
	}

	return string(ast.Format(descAst)), nil
}

// FIXME: this function is gross because of the weird logic cases that arises
// from having annotations that determine the type. I'm sure there's a much
// nicer way of writing this control flow.
func syzStructToSyzlang(s SyzStruct, constraintMap map[string]map[string]SyzConstraint,
	annotationMap map[string]map[string]SyzAnnotation) string {
	out := fmt.Sprintf("%s {\n", s.Name)
	for _, field := range s.Fields {
		out += "\t"
		typeName := dwarfToSyzlangType(field.TypeName)

		aSubMap, ok := annotationMap["struct "+s.Name]
		if ok {
			annotation, ok := aSubMap[field.Name]
			if !ok {
				goto append_type
			}

			// Annotated fields require special handling.
			switch annotation.Attribute {
			case AttributeLen:
				out += fmt.Sprintf("%s\tlen[%s, %s]", field.Name, annotation.LinkedFieldName, typeName)
			case AttributeString:
				out += fmt.Sprintf("%s\tptr[in, string]", field.Name)
			case AttributeArray:
				// An array type is prefixed with a leading "*", which we remove
				// to resolve the underlying type.
				arrayType := typeName[1:]
				out += fmt.Sprintf("%s\tptr[in, array[%s]]", field.Name, arrayType)
			}
			out += "\n"
			continue
		}

		// just appends the type as it appear in the
	append_type:
		out += fmt.Sprintf("%s\t%s", field.Name, typeName)

		subMap, ok := constraintMap["struct "+s.Name]
		if ok {
			constraint, ok := subMap[field.Name]
			if ok {
				out += syzConstraintToSyzlang(constraint)
			}
		}
		out += "\n"
	}
	out += "}"
	return out
}

func syzFuncToSyzlang(s SyzFunc) string {
	typeName := strings.TrimPrefix(s.InputStructName, "struct ")

	out := fmt.Sprintf("syz_kfuzztest_run$%s(", s.Name)
	out += fmt.Sprintf("name ptr[in, string[\"%s\"]], ", s.Name)
	out += fmt.Sprintf("data ptr[in, %s], ", typeName)
	out += "len bytesize[data])"
	// TODO:(ethangraham) The only other way I can think of getting this name
	// would involve using the "reflect" package and matching against the
	// KFuzzTest name, which isn't much better than hardcoding this.
	out += "(kfuzz_test)"

	return out
}

func syzConstraintToSyzlang(c SyzConstraint) string {
	switch c.ConstraintType {
	case ExpectEq:
		return fmt.Sprintf("[%d]", c.Value1)
	case ExpectLt:
		return fmt.Sprintf("[0:%d]", c.Value1-1)
	case ExpectLe:
		return fmt.Sprintf("[0:%d]", c.Value1)
	case ExpectGt:
		return fmt.Sprintf("[%d]", c.Value1+1)
	case ExpectGe:
		return fmt.Sprintf("[%d]", c.Value1)
	case ExpectInRange:
		return fmt.Sprintf("[%d:%d]", c.Value1, c.Value2)
	default:
		return ""
	}
}

func isArray(typeName string) (bool, string) {
	re := regexp.MustCompile(`^\[(\d+)\]([a-zA-Z]+)$`)
	matches := re.FindStringSubmatch(typeName)
	if len(matches) == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("array[%s, %s]", dwarfToSyzlangType(matches[2]), matches[1])
}

func dwarfToSyzlangType(typeName string) string {
	if after, ok := strings.CutPrefix(typeName, "struct "); ok {
		return after
	}

	if after, ok := strings.CutPrefix(typeName, "*const struct"); ok {
		return fmt.Sprintf("ptr[in, %s]", after)
	} else if after, ok := strings.CutPrefix(typeName, "*struct"); ok {
		return fmt.Sprintf("ptr[inout, %s]", after)
	}

	isArr, arr := isArray(typeName)
	if isArr {
		return arr
	}

	switch typeName {
	case "long unsigned int", "long int", "size_t":
		return "int64"
	case "int", "unsigned int":
		return "int32"
	case "char":
		return "int8"
	case "__u16":
		return "int16"
	case "*const char", "*const void", "*const unsigned char":
		return "ptr[in, array[int8]]" // const pointers are read-only
	case "*char", "*void":
		return "ptr[inout, array[int8]]"
	default:
		return typeName
	}
}
