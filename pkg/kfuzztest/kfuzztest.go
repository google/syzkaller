// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package kfuzztest exposes functions discovering KFuzzTest test cases from a
// vmlinux binary and parsing them into syzkaller-compatible formats.
// The general flow includes:
//   - Creating an Extractor that extracts these test cases from the binary
//   - Creating a Builder that takes the extractor's output and returns some
//     compatible encoding of the test cases that were discovered
package kfuzztest

import (
	"debug/dwarf"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/kcov"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type SyzField struct {
	Name      string
	dwarfType dwarf.Type
}

type SyzStruct struct {
	dwarfType *dwarf.StructType
	Name      string
	Fields    []SyzField
}

type SyzFunc struct {
	Name            string
	InputStructName string
}

type ConstraintType uint8

const (
	ExpectEq ConstraintType = iota
	ExpectNe
	ExpectLt
	ExpectLe
	ExpectGt
	ExpectGe
	ExpectInRange
)

func (c ConstraintType) String() string {
	return [...]string{"EXPECT_EQ", "EXPECT_NE", "EXPECT_LT", "EXPECT_LE", "EXPECT_GT", "EXPECT_GE", "EXPECT_IN_RANGE"}[c]
}

type SyzConstraint struct {
	InputType string
	FieldName string
	Value1    uintptr
	Value2    uintptr
	ConstraintType
}

type AnnotationAttribute uint8

const (
	AttributeLen AnnotationAttribute = iota
	AttributeString
	AttributeArray
)

func (a AnnotationAttribute) String() string {
	return [...]string{"ATTRIBUTE_LEN", "ATTRIBUTE_STRING", "ATTRIBUTE_ARRAY"}[a]
}

type SyzAnnotation struct {
	InputType       string
	FieldName       string
	LinkedFieldName string
	Attribute       AnnotationAttribute
}

// ExtractDescription returns a syzlang description of all discovered KFuzzTest
// targets, or an error on failure.
func ExtractDescription(vmlinuxPath string) (string, error) {
	extractor, err := NewExtractor(vmlinuxPath)
	if err != nil {
		return "", err
	}
	eRes, err := extractor.ExtractAll()
	if err != nil {
		return "", err
	}
	builder := NewBuilder(eRes.Funcs, eRes.Structs, eRes.Constraints, eRes.Annotations)
	return builder.EmitSyzlangDescription()
}

type KFuzzTestData struct {
	Description string
	Calls       []*prog.Syscall
	Resources   []*prog.ResourceDesc
	Types       []prog.Type
}

type extractKFuzzTestDataState struct {
	once sync.Once
	data KFuzzTestData
	err  error
}

var extractState extractKFuzzTestDataState

// ExtractData extracts KFuzzTest data from a vmlinux binary. The return value
// of this call is cached so that it can be safely called multiple times
// without incurring a new scan of a vmlinux image.
// NOTE: the implementation assumes the existence of only one vmlinux image
// per process, i.e. no attempt is made to distinguish different vmlinux images
// based on their path.
func ExtractData(vmlinuxPath string) (KFuzzTestData, error) {
	extractState.once.Do(func() {
		desc, err := ExtractDescription(vmlinuxPath)
		if err != nil {
			extractState.err = err
			return
		}

		var astError error
		eh := func(pos ast.Pos, msg string) {
			astError = fmt.Errorf("AST error: %v: %v\n", pos, msg)
		}
		descAst := ast.Parse([]byte(desc), "kfuzztest-autogen", eh)
		if astError != nil {
			extractState.err = astError
			return
		}
		if descAst == nil {
			extractState.err = fmt.Errorf("failed to build AST for program")
			return
		}

		target := targets.Get(targets.Linux, targets.AMD64)
		program := compiler.Compile(descAst, make(map[string]uint64), target, eh)
		if astError != nil {
			extractState.err = fmt.Errorf("failed to compile extracted KFuzzTest target: %v", astError)
		}

		kFuzzTestCalls := []*prog.Syscall{}
		for _, call := range program.Syscalls {
			// The generated descriptions contain some number of built-ins, which
			// we want to filter out.
			if call.Attrs.KFuzzTest {
				kFuzzTestCalls = append(kFuzzTestCalls, call)
			}
		}

		// We restore links on all restored system calls for completeness, but we
		// only return the filtered slice.
		prog.RestoreLinks(program.Syscalls, program.Resources, program.Types)

		extractState.data = KFuzzTestData{
			Description: desc,
			Calls:       kFuzzTestCalls,
			Resources:   program.Resources,
			Types:       program.Types,
		}
	})

	return extractState.data, extractState.err
}

// ActivateKFuzzTargets extracts all KFuzzTest targets from a vmlinux binary
// and extends a target with the discovered pseudo-syscalls.
func ActivateKFuzzTargets(target *prog.Target, vmlinuxPath string) ([]*prog.Syscall, error) {
	data, err := ExtractData(vmlinuxPath)
	if err != nil {
		return nil, err
	}
	// TODO: comment this properly. It's important to note here that despite
	// extending the target, correct encoding relies on syz_kfuzztest_run being
	// compiled into the target, and its ID being available.
	target.Extend(data.Calls, data.Types, data.Resources)
	return data.Calls, nil
}

func ExecKFuzzTestCallLocal(st *kcov.KCOVState, call *prog.Call) ([]uintptr, error) {
	if !call.Meta.Attrs.KFuzzTest {
		return []uintptr{}, fmt.Errorf("call is not a KFuzzTest call")
	}
	testName, isKFuzzTest := GetTestName(call.Meta)
	if !isKFuzzTest {
		return []uintptr{}, fmt.Errorf("tried to execute a syscall that wasn't syz_kfuzztest_run")
	}

	dataArg, ok := call.Args[1].(*prog.PointerArg)
	if !ok {
		return []uintptr{}, fmt.Errorf("second arg for syz_kfuzztest_run should be a pointer")
	}
	finalBlob := prog.MarshallKFuzztestArg(dataArg.Res)
	inputPath := GetInputFilepath(testName)

	res := st.Trace(func() error { return os.WriteFile(inputPath, finalBlob, 0644) })
	return res.Coverage, res.Result
}

const syzKfuzzTestRun string = "syz_kfuzztest_run"

// Common prefix that all discriminated syz_kfuzztest_run pseudo-syscalls share.
const KfuzzTestTargetPrefix string = syzKfuzzTestRun + "$"

func GetTestName(syscall *prog.Syscall) (string, bool) {
	if syscall.CallName != syzKfuzzTestRun {
		return "", false
	}
	return strings.CutPrefix(syscall.Name, KfuzzTestTargetPrefix)
}

const kFuzzTestDir string = "/sys/kernel/debug/kfuzztest"
const inputFile string = "input"

func GetInputFilepath(testName string) string {
	return path.Join(kFuzzTestDir, testName, inputFile)
}
