// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzlang"
	"github.com/google/syzkaller/pkg/ast"
)

var (
	syscallRegex = regexp.MustCompile(`(?:[a-zA-Z0-9_]+\s*=\s*)?([a-zA-Z0-9_$\.]+)\s*\(`)
	astCacheMu   sync.Mutex
	astCache     = make(map[string]*astDescriptionInfo)
)

type astDescriptionInfo struct {
	syscalls map[string]*ast.Call
	types    map[string]ast.Node
}

func getASTDescriptionInfo(syzkallerDir, osTarget string) (*astDescriptionInfo, error) {
	astCacheMu.Lock()
	defer astCacheMu.Unlock()

	key := osTarget + ":" + syzkallerDir
	if info, ok := astCache[key]; ok {
		return info, nil
	}

	sysFS := syzlang.GetSyzFS()
	if sysFS == nil {
		sysFS = syzlang.NewSyzFS(syzkallerDir, osTarget)
	}
	files := DescriptionFiles(osTarget)

	info := &astDescriptionInfo{
		syscalls: make(map[string]*ast.Call),
		types:    make(map[string]ast.Node),
	}

	errorHandler := func(pos ast.Pos, msg string) {}

	for _, file := range files {
		if strings.HasSuffix(file, ".const") || strings.HasPrefix(file, "test/") {
			continue
		}
		data, err := sysFS.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read description file %s: %w", file, err)
		}
		desc := ast.Parse(data, file, errorHandler)
		if desc == nil {
			continue
		}
		for _, node := range desc.Nodes {
			_, typ, name := node.Info()
			if typ == "syscall" {
				if call, ok := node.(*ast.Call); ok {
					info.syscalls[name] = call
				}
			} else if name != "" {
				info.types[name] = node
			}
		}
	}

	astCache[key] = info
	return info, nil
}

func extractSyscalls(program string) []string {
	var syscalls []string
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(program, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		matches := syscallRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			name := matches[1]
			if !seen[name] {
				seen[name] = true
				syscalls = append(syscalls, name)
			}
		}
	}
	return syscalls
}

func collectDependencies(info *astDescriptionInfo, syscallNames []string) ([]ast.Node, error) {
	referencedNodes := make(map[string]ast.Node)
	var queue []string

	addType := func(ident string) {
		if ident == "" {
			return
		}
		if _, seen := referencedNodes[ident]; seen {
			return
		}
		if node, ok := info.types[ident]; ok {
			referencedNodes[ident] = node
			queue = append(queue, ident)
		}
	}

	var traverseType func(t *ast.Type)
	traverseType = func(t *ast.Type) {
		if t == nil {
			return
		}
		addType(t.Ident)
		for _, arg := range t.Args {
			traverseType(arg)
		}
		for _, col := range t.Colon {
			traverseType(col)
		}
	}

	traverseStruct := func(s *ast.Struct) {
		for _, field := range s.Fields {
			traverseType(field.Type)
		}
	}

	var syscallNodes []ast.Node
	for _, name := range syscallNames {
		if callNode, ok := info.syscalls[name]; ok {
			syscallNodes = append(syscallNodes, callNode)
			for _, arg := range callNode.Args {
				traverseType(arg.Type)
			}
			traverseType(callNode.Ret)
		}
	}

	for len(queue) > 0 {
		ident := queue[0]
		queue = queue[1:]

		node := referencedNodes[ident]
		switch n := node.(type) {
		case *ast.Struct:
			traverseStruct(n)
		case *ast.Resource:
			traverseType(n.Base)
		case *ast.TypeDef:
			traverseType(n.Type)
			if n.Struct != nil {
				traverseStruct(n.Struct)
			}
		}
	}

	var allNodes []ast.Node
	allNodes = append(allNodes, syscallNodes...)

	for _, name := range slices.Sorted(maps.Keys(referencedNodes)) {
		allNodes = append(allNodes, referencedNodes[name])
	}

	return allNodes, nil
}

// ResolveSyzlangDependencies is the PreExecute hook callback for CodeFixer.
func ResolveSyzlangDependencies(ctx *aflow.Context, _ struct{}, args CodeFixerArgs) (map[string]any, error) {
	if args.SyzProgram == "" {
		return map[string]any{"StaticDefinitions": ""}, nil
	}

	targetOS, _ := ctx.StateMap()["TargetOS"].(string)
	if targetOS == "" {
		targetOS = "linux"
	}
	syzkaller, _ := ctx.StateMap()["Syzkaller"].(string)

	info, err := getASTDescriptionInfo(syzkaller, targetOS)
	if err != nil {
		return nil, err
	}

	syscalls := extractSyscalls(args.SyzProgram)
	nodes, err := collectDependencies(info, syscalls)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	for _, node := range nodes {
		sb.WriteString(ast.SerializeNode(node))
		sb.WriteString("\n")
	}
	return map[string]any{"StaticDefinitions": sb.String()}, nil
}
