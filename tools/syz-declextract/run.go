// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/targets"
)

const sendmsg = "sendmsg"

type compileCommand struct {
	Command   string
	Directory string
	File      string
}

type output struct {
	stdout string
	stderr string
}

const ( // Output Format.
	Final   = "final"
	Minimal = "minimal"
)

func main() {
	var (
		binary    = flag.String("binary", "syz-declextract", "path to binary")
		outFile   = flag.String("output", "out.txt", "output file")
		sourceDir = flag.String("sourcedir", "", "kernel source directory")
		buildDir  = flag.String("builddir", "", "kernel build directory (defaults to source directory)")
		format    = flag.String("output_format", Final, "format for output [minimal, final]")
	)
	defer tool.Init()()

	switch *format {
	case Final, Minimal:
	default:
		tool.Failf("invalid -output_format flag value [minimal, final]")
	}
	if *sourceDir == "" {
		tool.Failf("path to kernel source directory is required")
	}
	if *buildDir == "" {
		*buildDir = *sourceDir
	}
	*sourceDir = filepath.Clean(osutil.Abs(*sourceDir))
	*buildDir = filepath.Clean(osutil.Abs(*buildDir))

	compilationDatabase := filepath.Join(*buildDir, "compile_commands.json")
	fileData, err := os.ReadFile(compilationDatabase)
	if err != nil {
		tool.Fail(err)
	}

	var cmds []compileCommand
	if err := json.Unmarshal(fileData, &cmds); err != nil {
		tool.Fail(err)
	}

	outputs := make(chan output, len(cmds))
	files := make(chan string, len(cmds))
	for w := 0; w < runtime.NumCPU(); w++ {
		go worker(outputs, files, *binary, compilationDatabase, *format)
	}

	for _, cmd := range cmds {
		// Files compiled with gcc are not a part of the kernel
		// (assuming compile commands were generated with make CC=clang).
		// They are probably a part of some host tool.
		if !strings.HasSuffix(cmd.File, ".c") || strings.HasPrefix(cmd.Command, "gcc") {
			outputs <- output{}
			continue
		}
		files <- cmd.File
	}
	close(files)

	var nodes []ast.Node
	syscallNames := readSyscallNames(filepath.Join(*sourceDir, "arch"))

	var minimalOutput []string
	eh := ast.LoggingHandler
	for range cmds {
		out := <-outputs
		if out.stderr != "" {
			tool.Failf("%s", out.stderr)
		}
		if *format == Minimal {
			minimalOutput = append(minimalOutput, getMinimalOutput(out.stdout, syscallNames)...)
			continue
		}
		parse := ast.Parse([]byte(out.stdout), "", eh)
		if parse == nil {
			tool.Failf("parsing error")
		}
		appendNodes(&nodes, parse.Nodes, syscallNames, *sourceDir, *buildDir)
	}

	var out []byte
	if *format == Minimal {
		slices.Sort(minimalOutput)
		minimalOutput = slices.Compact(minimalOutput)
		out = []byte(strings.Join(minimalOutput, "\n"))
	} else {
		out = makeOutput(nodes)
	}

	if err := os.WriteFile(*outFile, out, 0666); err != nil {
		tool.Fail(err)
	}
}

func getMinimalOutput(out string, syscallNames map[string][]string) []string {
	var minimalOutput []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		const SYSCALL = "SYSCALL"
		if !strings.HasPrefix(line, SYSCALL) {
			minimalOutput = append(minimalOutput, line)
			continue
		}
		oldName := line[len(SYSCALL)+1:]
		if !shouldRenameSyscall(oldName) {
			minimalOutput = append(minimalOutput, line)
			continue
		}
		for _, newName := range syscallNames[oldName] {
			if isProhibited(newName) {
				continue
			}
			minimalOutput = append(minimalOutput, strings.Replace(line, oldName, newName, 1))
		}
	}
	return minimalOutput
}

func makeOutput(nodes []ast.Node) []byte {
	slices.SortFunc(nodes, func(a, b ast.Node) int {
		return strings.Compare(ast.SerializeNode(a), ast.SerializeNode(b))
	})
	nodes = slices.CompactFunc(nodes, func(a, b ast.Node) bool {
		return ast.SerializeNode(a) == ast.SerializeNode(b)
	})
	slices.SortStableFunc(nodes, func(a, b ast.Node) int {
		return getTypeOrder(a) - getTypeOrder(b)
	})

	var syscalls []*ast.Call
	var structs []*ast.Struct
	for _, node := range nodes {
		switch node := node.(type) {
		case *ast.Call:
			syscalls = append(syscalls, node)
		case *ast.Struct:
			// Special case for unsued struct. TODO: handle unused structs.
			if node.Name.Name == "utimbuf$auto_record" { // NOTE: Causes side effect when truncating nodes after the loop
				continue
			}
			structs = append(structs, node)
		case *ast.Include, *ast.TypeDef, *ast.Resource, *ast.IntFlags, *ast.NewLine:
			continue
		default:
			_, typ, _ := node.Info()
			tool.Failf("unhandled Node type: %v", typ)
		}
	}
	// NOTE: The -2 at the end is to account for one unused struct and one newline
	nodes = nodes[:len(nodes)-len(structs)-len(syscalls)-2]

	sendmsgNo := 0
	// Some commands are executed for multiple policies. Ensure that they don't get deleted by the following compact call.
	for i := 1; i < len(syscalls); i++ {
		if syscalls[i].CallName == sendmsg && syscalls[i].Name.Name == syscalls[i-1].Name.Name {
			syscalls[i].Name.Name += strconv.Itoa(sendmsgNo)
			sendmsgNo++
		}
	}
	syscalls = slices.CompactFunc(syscalls, func(a, b *ast.Call) bool {
		// We only compare the the system call names for cases where the same system call has different parameter names,
		// but share the same syzkaller type. NOTE:Change when we have better type extraction.
		return a.Name.Name == b.Name.Name
	})

	autoGeneratedNotice := "# Code generated by syz-declextract. DO NOT EDIT.\n"
	commonKernelHeaders := "include <include/vdso/bits.h>\ninclude <include/linux/types.h>"
	var netlinkNames []string
	mmap2 := "_ = __NR_mmap2\n"
	eh := ast.LoggingHandler
	desc := ast.Parse([]byte(autoGeneratedNotice+commonKernelHeaders), "", eh)
	desc.Nodes = append(desc.Nodes, nodes...)
	usedNetlink := make(map[string]bool)
	for _, node := range syscalls {
		if node.CallName == sendmsg && len(node.Args[1].Type.Args) == 2 && len(node.Args[1].Type.Args[1].Args) > 1 {
			policy := node.Args[1].Type.Args[1].Args[1].Ident
			usedNetlink[policy] = true
			_, isDefined := slices.BinarySearchFunc(structs, policy, func(a *ast.Struct, b string) int {
				return strings.Compare(a.Name.Name, b)
			})
			if !isDefined {
				continue
			}
		}
		desc.Nodes = append(desc.Nodes, node)
	}
	desc.Nodes = append(desc.Nodes, ast.Parse([]byte(mmap2), "", eh).Nodes...)
	for _, node := range structs {
		desc.Nodes = append(desc.Nodes, node)
		name := node.Name.Name
		if !usedNetlink[name] && !strings.HasSuffix(name, "$auto_record") {
			netlinkNames = append(netlinkNames, name)
		}
	}
	for i, structName := range netlinkNames {
		netlinkNames[i] = fmt.Sprintf("\tpolicy%v msghdr_auto[%v]\n", i, structName)
	}
	netlinkUnion := `
type msghdr_auto[POLICY] msghdr_netlink[netlink_msg_t[autogenerated_netlink, genlmsghdr, POLICY]]
resource autogenerated_netlink[int16]
syz_genetlink_get_family_id$auto(name ptr[in, string], fd sock_nl_generic) autogenerated_netlink
sendmsg$autorun(fd sock_nl_generic, msg ptr[in, auto_union], f flags[send_flags])
auto_union [
` + strings.Join(netlinkNames, "") + "]"
	netlinkUnionParsed := ast.Parse([]byte(netlinkUnion), "", eh)
	if netlinkUnionParsed == nil {
		tool.Failf("parsing error")
	}
	desc.Nodes = append(desc.Nodes, netlinkUnionParsed.Nodes...)

	// New lines are added in the parsing step. This is why we need to Format (serialize the description), Parse, then
	// Format again.
	return ast.Format(ast.Parse(ast.Format(desc), "", eh))
}

func worker(outputs chan output, files chan string, binary, compilationDatabase, format string) {
	for file := range files {
		cmd := exec.Command(binary, "-p", compilationDatabase, file, fmt.Sprintf("--%s", format))
		stdout, err := cmd.Output()
		var stderr string
		if err != nil {
			var error *exec.ExitError
			if errors.As(err, &error) {
				if len(error.Stderr) != 0 {
					stderr = fmt.Sprintf("%v: %v", file, string(error.Stderr))
				} else {
					stderr = fmt.Sprintf("%v: %v", file, error.String())
				}
			} else {
				stderr = fmt.Sprintf("%v: %v", file, error)
			}
		}
		outputs <- output{string(stdout), stderr}
	}
}

func renameSyscall(syscall *ast.Call, rename map[string][]string) []ast.Node {
	if !shouldRenameSyscall(syscall.CallName) {
		return []ast.Node{syscall}
	}
	var renamed []ast.Node
	toReplace := syscall.CallName
	if rename[toReplace] == nil {
		// Syscall has no record in the tables for the architectures we support.
		return nil
	}

	for _, name := range rename[toReplace] {
		if isProhibited(name) {
			continue
		}
		newCall := syscall.Clone().(*ast.Call)
		newCall.Name.Name = name + "$auto"
		newCall.CallName = name // Not required	but avoids mistakenly treating CallName as the part before the $.
		renamed = append(renamed, newCall)
	}

	return renamed
}

func readSyscallNames(kernelDir string) map[string][]string {
	var rename = make(map[string][]string)
	for _, arch := range targets.List[targets.Linux] {
		filepath.Walk(filepath.Join(kernelDir, arch.KernelHeaderArch),
			func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !strings.HasSuffix(path, ".tbl") {
					return nil
				}
				fi, err := os.Lstat(path)
				if err != nil {
					tool.Fail(err)
				}
				if fi.Mode()&fs.ModeSymlink != 0 { // Some symlinks link to files outside of arch directory.
					return nil
				}
				f, err := os.Open(path)
				if err != nil {
					tool.Fail(err)
				}
				s := bufio.NewScanner(f)
				for s.Scan() {
					fields := strings.Fields(s.Text())
					if len(fields) < 4 || fields[0] == "#" || strings.HasPrefix(fields[2], "unused") || fields[3] == "-" ||
						strings.HasPrefix(fields[3], "compat") || strings.HasPrefix(fields[3], "sys_ia32") ||
						fields[3] == "sys_ni_syscall" {
						// System calls prefixed with ia32 are ignored due to conflicting system calls for 64 bit and 32 bit.
						continue
					}
					key := strings.TrimPrefix(fields[3], "sys_")
					rename[key] = append(rename[key], fields[2])
				}
				return nil
			})
	}

	for k := range rename {
		slices.Sort(rename[k])
		rename[k] = slices.Compact(rename[k])
	}

	return rename
}

func shouldRenameSyscall(syscall string) bool {
	switch syscall {
	case sendmsg, "syz_genetlink_get_family_id":
		return false
	default:
		return true
	}
}

func isProhibited(syscall string) bool {
	switch syscall {
	case "reboot", "utimesat": // `utimesat` is not defined for all arches.
		return true
	default:
		return false
	}
}

func appendNodes(slice *[]ast.Node, nodes []ast.Node, syscallNames map[string][]string, sourceDir, buildDir string) {
	for _, node := range nodes {
		switch node := node.(type) {
		case *ast.Call:
			// Some syscalls have different names and entry points and thus need to be renamed.
			// e.g. SYSCALL_DEFINE1(setuid16, old_uid_t, uid) is referred to in the .tbl file with setuid.
			*slice = append(*slice, renameSyscall(node, syscallNames)...)
		case *ast.Include:
			if file, err := filepath.Rel(sourceDir, filepath.Join(buildDir, node.File.Value)); err == nil {
				node.File.Value = file
			}
			*slice = append(*slice, node)
		default:
			*slice = append(*slice, node)
		}
	}
}

func getTypeOrder(a ast.Node) int {
	switch a.(type) {
	case *ast.Include:
		return 0
	case *ast.IntFlags:
		return 1
	case *ast.Resource:
		return 2
	case *ast.TypeDef:
		return 3
	case *ast.Call:
		return 4
	case *ast.Struct:
		return 5
	case *ast.NewLine:
		return 6
	default:
		return -1
	}
}
