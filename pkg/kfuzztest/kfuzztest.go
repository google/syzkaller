// Package kfuzztest exposes functions discovering KFuzzTest test cases from a
// vmlinux binary and parsing them into syzkaller-compatible formats.
// The general flow includes:
//   - Creating an Extractor that extracts these test cases from the binary
//   - Creating a Builder that takes the extractor's output and returns some
//     compatible encoding of the test cases that were discovered
package kfuzztest

import (
	"fmt"
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

// ExtractProg extracts a compiler.Prog from VMLinux containing all of the
// discovered KFuzzTest target definitions
func ExtractProg(vmlinuxPath string) (*compiler.Prog, error) {
	extractor, err := NewExtractor(vmlinuxPath)
	if err != nil {
		return nil, err
	}
	funcs, structs, constraints, err := extractor.ExtractAll()
	if err != nil {
		return nil, err
	}

	fmt.Printf("dumping constraints...\n")
	for _, constraint := range constraints {
		fmt.Printf("\tInputType: %s\n", constraint.InputType)
		fmt.Printf("\tFieldName: %s\n", constraint.FieldName)
		fmt.Printf("\tType:      %s\n", constraint.ConstraintType.String())
	}

	builder := NewBuilder(funcs, structs, constraints)
	desc := builder.EmitSyzlangDescription()

	fmt.Printf("Syzlang formatted KFuzzTest targets:\n\n")
	fmt.Println(desc)
	fmt.Printf("\n\n")

	// XXX: Error handler that just makes the program panic - we ideally want
	// to be returning something up to the caller rather than doing this.
	eh := func(pos ast.Pos, msg string) {
		panic(fmt.Sprintf("Failure: %v: %v\n", pos, msg))
	}
	descAst := ast.Parse([]byte(desc), "file.txt", eh)
	if descAst == nil {
		return nil, fmt.Errorf("Failed to build AST for program\n")
	}

	for _, node := range descAst.Nodes {
		_, _, name := node.Info()
		fmt.Printf("\t%s\n", name)
	}

	target := targets.Get(targets.Linux, targets.AMD64)
	program := compiler.Compile(descAst, make(map[string]uint64), target, eh)
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

	if newProg != nil {
		// we can only enable the new syscalls if the ID was found as this
		// description as well as it's corresponding pseudo-syscall need to
		// be built into syzkaller.
		prog.RestoreLinks(newProg.Syscalls, newProg.Resources, newProg.Types)
		cfg.Target.Syscalls = append(cfg.Target.Syscalls, newProg.Syscalls...)
		cfg.Target.Types = append(cfg.Target.Types, newProg.Types...)
		cfg.Target.Resources = append(cfg.Target.Resources, newProg.Resources...)
		cfg.Target.InitTarget()

		// append these new syscalls
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
