// Package kfuzztest exposes functions discovering KFuzzTest test cases from a
// vmlinux binary and parsing them into syzkaller-compatible formats.
// The general flow includes:
//   - Creating an Extractor that extracts these test cases from the binary
//   - Creating a Builder that takes the extractor's output and returns some
//     compatible encoding of the test cases that were discovered
package kfuzztest

import (
	"fmt"
	"os"
	"path"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type SyzField struct {
	Name     string
	TypeName string
}

type SyzStruct struct {
	Name   string
	Fields []SyzField
}

type SyzFunc struct {
	Name            string
	InputStructName string
}

type ConstraintType uint8

const (
	ExpectEq ConstraintType = iota
	ExpectNe
	ExpectLe
	ExpectGt
	ExpectInRange
)

func (c ConstraintType) String() string {
	return [...]string{"EXPECT_EQ", "EXPECT_NE", "EXPECT_LE", "EXPECT_GT", "EXPECT_IN_RANGE"}[c]
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

// ExtractProg extracts a compiler.Prog from VMLinux containing all of the
// discovered KFuzzTest target definitions, resources, and types.
func ExtractProg(vmlinuxPath string) (*compiler.Prog, error) {
	desc, err := ExtractDescription(vmlinuxPath)
	if err != nil {
		return nil, err
	}

	var astError error
	eh := func(pos ast.Pos, msg string) {
		astError = fmt.Errorf("AST error: %v: %v\n", pos, msg)
	}
	descAst := ast.Parse([]byte(desc), "kfuzztest-autogen", eh)
	if astError != nil {
		return nil, astError
	}
	if descAst == nil {
		return nil, fmt.Errorf("failed to build AST for program")
	}

	target := targets.Get(targets.Linux, targets.AMD64)
	program := compiler.Compile(descAst, make(map[string]uint64), target, eh)
	if program == nil {
		return nil, fmt.Errorf("failed to compile extracted KFuzzTest target")
	}

	prog.RestoreLinks(program.Syscalls, program.Resources, program.Types)
	return program, nil
}

// EnableKFuzzTargets enabled KFuzzTest targets that are discovered in the
// vmlinux binary pointed to by the manager configuation. This assumes that
// the config has lready been loaded, for example via cfg.LoadFile in the
// main function of the syz-manager program.
func EnableKFuzzTargets(cfg *mgrconfig.Config) error {
	vmLinuxPath := path.Join(cfg.KernelObj, "vmlinux")
	newProg, err := ExtractProg(vmLinuxPath)
	if err != nil {
		return err
	}

	// we can only enable the new syscalls if the ID was found as this
	// description as well as it's corresponding pseudo-syscall need to
	// be built into syzkaller.
	if newProg != nil {
		cfg.Target.ApplyKFuzzProg(newProg.Syscalls, newProg.Types, newProg.Resources)

		for _, syscall := range newProg.Syscalls {
			// give the right ID to this new syscall
			// syscall.ID = syzKFuzzTestID
			// enable it (no sure if this does anything yet)
			cfg.EnabledSyscalls = append(cfg.EnabledSyscalls, syscall.Name)
			// update the syscall map to point to this!
			// cfg.Target.Syscalls[syzKFuzzTestID] = syscall
			cfg.Syscalls = append(cfg.Syscalls, syscall.ID)
		}
	}

	return nil
}

// XXX: Duplicate code. Refactor.
func ActivateKFuzzTargets(vmLinuxPath string, target *prog.Target, enabledCalls *map[*prog.Syscall]bool) error {
	newProg, err := ExtractProg(vmLinuxPath)
	// If newProg is nil, then err is always non-nil.
	if err != nil {
		return err
	}

	// We can only enable the new syscalls if the ID was found as this
	// description as well as it's corresponding pseudo-syscall need to
	// be built into syzkaller.
	target.ApplyKFuzzProg(newProg.Syscalls, newProg.Types, newProg.Resources)

	// Enable discovered syscalls.
	for _, syscall := range newProg.Syscalls {
		(*enabledCalls)[syscall] = true
	}
	return nil
}

func ExecKFuzzTestCallLocal(call *prog.Call) error {
	testName, isKFuzzTest := GetTestName(call.Meta)
	if !isKFuzzTest {
		return fmt.Errorf("tried to execute a syscall that wasn't syz_kfuzztest_run")
	}

	dataArg, ok := call.Args[1].(*prog.PointerArg)
	if !ok {
		return fmt.Errorf("second arg for syz_kfuzztest_run should be a pointer")
	}
	finalBlob := prog.MarshallKFuzztestArg(dataArg.Res)
	inputPath := path.Join("/sys/kernel/debug/kfuzztest/", testName, "input")
	return os.WriteFile(inputPath, finalBlob, 0644)
}
