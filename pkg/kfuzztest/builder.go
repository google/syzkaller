package kfuzztest

import (
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
	sortedStructs := b.topologicalSortDependencyDag()
	for _, s := range sortedStructs {
		descBuilder.WriteString(syzStructToSyzlang(s, constraintMap, annotationMap))
		descBuilder.WriteString("\n\n")
	}

	for _, fn := range b.funcs {
		descBuilder.WriteString(syzFuncToSyzlang(fn))
		descBuilder.WriteString("\n")
	}

	eh := func(pos ast.Pos, msg string) {
		panic(fmt.Sprintf("Failure: %v: %v\n", pos, msg))
	}
	// Format the output syzlang descriptions.
	descAst := ast.Parse([]byte(descBuilder.String()), "", eh)
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
				out += fmt.Sprintf("%s\tptr[in, array[%s]]", field.Name, typeName)
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

	return out
}

func syzConstraintToSyzlang(c SyzConstraint) string {
	switch c.ConstraintType {
	case ExpectEq:
		return fmt.Sprintf("[%d]", c.Value1)
	case ExpectLe:
		return fmt.Sprintf("[:%d]", c.Value1) // this is strictly less than right?
	case ExpectGt:
		return fmt.Sprintf("[:%d]", c.Value1)
	case ExpectInRange:
		return fmt.Sprintf("[%d:%d]", c.Value1, c.Value2)
	default:
		return ""
	}
}

// Topologically sorts the builder's struct fields based on dependencies.
// This implementation assumes that the graph is acyclic which we can't assume
// in general but it will suffice for the time being.
func (b *Builder) topologicalSortDependencyDag() []SyzStruct {
	// maps type name to type name
	edges := make(map[string][]string)
	// map type name to SyzStruct instance so that we can output these more
	// easily
	nameToStruct := make(map[string]SyzStruct)
	for _, s := range b.structs {
		nameToStruct[s.Name] = s
	}

	for _, s := range b.structs {
		if _, ok := edges[s.Name]; !ok {
			edges[s.Name] = make([]string, 0)
		}

		for _, f := range s.Fields {
			edges[s.Name] = append(edges[s.Name], f.TypeName)
		}
	}

	// Assemble list of start nodes which are those with no incoming edges
	startNodes := make(map[string]bool)
	for _, node := range b.structs {
		startNodes[node.Name] = true
	}
	for _, nodes := range edges {
		for _, node := range nodes {
			if startNodes[node] {
				delete(startNodes, node)
			}
		}
	}

	sortedNames := make([]string, 0)
	var visit func(string, *map[string]bool)
	visit = func(node string, visited *map[string]bool) {
		sortedNames = append([]string{node}, sortedNames...)
		for _, child := range edges[node] {
			// this child is not a structure, so we don't need to visit
			if _, contained := nameToStruct[child]; !contained {
				continue
			}
			if _, ok := (*visited)[child]; !ok {
				(*visited)[child] = true
				visit(child, visited)
			}
		}
	}

	visited := make(map[string]bool)
	for node := range startNodes {
		if _, contains := visited[node]; !contains {
			visit(node, &visited)
		}
	}

	sortedStructs := make([]SyzStruct, len(sortedNames))
	for i, name := range sortedNames {
		sortedStructs[i] = nameToStruct[name]
	}

	return sortedStructs
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

	switch typeName {
	case "long unsigned int", "size_t":
		return "int64"
	case "int":
		return "int32"
	case "char":
		return "int8"
	case "__u16":
		return "int16"
	case "*const char", "*const void", "*const unsigned char":
		return "ptr[in, array[int8]]" // const pointers are read-only
	case "*char":
		return "ptr[inout, array[int8]]"
	default:
		return typeName
	}
}
