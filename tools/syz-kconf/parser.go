// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/vcs"
	"gopkg.in/yaml.v3"
)

type Instance struct {
	Name      string
	Kernel    Kernel
	Compiler  string
	Linker    string
	Verbatim  []byte
	Shell     []Shell
	Features  Features
	ConfigMap map[string]*Config
	Configs   []*Config
}

type Config struct {
	Name        string
	Value       string
	Optional    bool
	Constraints []string
	File        string
	Line        int
}

type Kernel struct {
	Repo string
	Tag  string
}

type Shell struct {
	Cmd         string
	Constraints []string
}

type Features map[string]bool

func (features Features) Match(constraints []string) bool {
	for _, feat := range constraints {
		if feat[0] == '-' {
			if features[feat[1:]] {
				return false
			}
		} else if !features[feat] {
			return false
		}
	}
	return true
}

func constraintsInclude(constraints []string, what string) bool {
	for _, feat := range constraints {
		if feat == what {
			return true
		}
	}
	return false
}

type rawMain struct {
	Instances []map[string][]string
	Includes  []map[string][]string
}

type rawFile struct {
	Kernel struct {
		Repo string
		Tag  string
	}
	Compiler string
	Linker   string
	Shell    []yaml.Node
	Verbatim string
	Config   []yaml.Node
}

func parseMainSpec(file string) ([]*Instance, []string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	raw := new(rawMain)
	if err := dec.Decode(raw); err != nil {
		return nil, nil, fmt.Errorf("failed to parse %v: %w", file, err)
	}
	var unusedFeatures []string
	var instances []*Instance
	for _, inst := range raw.Instances {
		for name, features := range inst {
			if name == "_" {
				unusedFeatures = features
				continue
			}
			inst, err := parseInstance(name, filepath.Dir(file), features, raw.Includes)
			if err != nil {
				return nil, nil, fmt.Errorf("%v: %w", name, err)
			}
			instances = append(instances, inst)
			inst, err = parseInstance(name+"-base", filepath.Dir(file),
				append(features, featBaseline, featBaseConfig), raw.Includes)
			if err != nil {
				return nil, nil, err
			}
			instances = append(instances, inst)
		}
	}
	return instances, unusedFeatures, nil
}

func parseInstance(name, configDir string, features []string, includes []map[string][]string) (*Instance, error) {
	inst := &Instance{
		Name:      name,
		Features:  make(Features),
		ConfigMap: make(map[string]*Config),
	}
	for _, feat := range features {
		inst.Features[feat] = true
	}
	errs := new(Errors)
	for _, include := range includes {
		for file, features := range include {
			raw, err := parseFile(filepath.Join(configDir, "bits", file))
			if err != nil {
				return nil, err
			}
			if inst.Features.Match(features) {
				mergeFile(inst, raw, file, errs)
			} else if inst.Features[featReduced] && constraintsInclude(features, "-"+featReduced) {
				// For fragments that we exclude because of "reduced" config,
				// we want to disable all configs listed there.
				// For example, if the fragment enables config FOO, and we the defconfig
				// also enabled FOO, we want to disable FOO to get reduced config.
				for _, node := range raw.Config {
					mergeConfig(inst, file, node, true, errs)
				}
			}
		}
	}
	inst.Verbatim = bytes.TrimSpace(inst.Verbatim)
	return inst, errs.err()
}

func parseFile(file string) (*rawFile, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %w", file, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	raw := new(rawFile)
	if err := dec.Decode(raw); err != nil {
		return nil, fmt.Errorf("failed to parse %v: %w", file, err)
	}
	return raw, nil
}

func mergeFile(inst *Instance, raw *rawFile, file string, errs *Errors) {
	if raw.Kernel.Repo != "" || raw.Kernel.Tag != "" {
		if !vcs.CheckRepoAddress(raw.Kernel.Repo) {
			errs.push("%v: bad kernel repo %q", file, raw.Kernel.Repo)
		}
		if !vcs.CheckBranch(raw.Kernel.Tag) {
			errs.push("%v: bad kernel tag %q", file, raw.Kernel.Tag)
		}
		if inst.Kernel.Repo != "" {
			errs.push("%v: kernel is set twice", file)
		}
		inst.Kernel = raw.Kernel
	}
	if raw.Compiler != "" {
		if inst.Compiler != "" {
			errs.push("%v: compiler is set twice", file)
		}
		inst.Compiler = raw.Compiler
	}
	if raw.Linker != "" {
		if inst.Linker != "" {
			errs.push("%v: linker is set twice", file)
		}
		inst.Linker = raw.Linker
	}
	prependShell := []Shell{}
	for _, node := range raw.Shell {
		cmd, _, constraints, err := parseNode(node)
		if err != nil {
			errs.push("%v:%v: %v", file, node.Line, err)
		}
		prependShell = append(prependShell, Shell{
			Cmd:         cmd,
			Constraints: constraints,
		})
	}
	inst.Shell = append(prependShell, inst.Shell...)
	if raw.Verbatim != "" {
		inst.Verbatim = append(append(inst.Verbatim, strings.TrimSpace(raw.Verbatim)...), '\n')
	}
	for _, node := range raw.Config {
		mergeConfig(inst, file, node, false, errs)
	}
}

func mergeConfig(inst *Instance, file string, node yaml.Node, reduced bool, errs *Errors) {
	name, val, constraints, err := parseNode(node)
	if err != nil {
		errs.push("%v:%v: %v", file, node.Line, err)
		return
	}
	if reduced {
		if val != kconfig.No && val != kconfig.Yes {
			return
		}
		val = kconfig.No
		constraints = append(constraints, featWeak)
	}
	cfg := &Config{
		Name:  name,
		Value: val,
		File:  file,
		Line:  node.Line,
	}
	override, appendVal := false, false
	for _, feat := range constraints {
		switch feat {
		case featOverride:
			override = true
		case featOptional:
			cfg.Optional = true
		case featWeak:
			override, cfg.Optional = true, true
		case featAppend:
			override, appendVal = true, true
		default:
			cfg.Constraints = append(cfg.Constraints, feat)
		}
	}
	if prev := inst.ConfigMap[name]; prev != nil {
		if !override {
			errs.push("%v:%v: %v is already defined at %v:%v", file, node.Line, name, prev.File, prev.Line)
		}
		if appendVal {
			a, b := prev.Value, cfg.Value
			if a == "" || a[len(a)-1] != '"' || b == "" || b[0] != '"' {
				errs.push("%v:%v: bad values to append, want non-empty strings", file, node.Line)
				return
			}
			prev.Value = a[:len(a)-1] + " " + b[1:]
		} else {
			*prev = *cfg
		}
		return
	}
	if override && !cfg.Optional {
		errs.push("%v:%v: %v nothing to override", file, node.Line, name)
	}
	inst.ConfigMap[name] = cfg
	inst.Configs = append(inst.Configs, cfg)
}

func parseNode(node yaml.Node) (name, val string, constraints []string, err error) {
	// Simplest case: - FOO.
	val = kconfig.Yes
	if node.Decode(&name) == nil {
		return
	}
	complexVal := make(map[string]yaml.Node)
	if err = node.Decode(complexVal); err != nil {
		return
	}
	var valNode yaml.Node
	for k, v := range complexVal {
		name, valNode = k, v
		break
	}
	// Case: - FOO: 42.
	if intVal := 0; valNode.Decode(&intVal) == nil {
		val = fmt.Sprint(intVal)
		return
	}
	if valNode.Decode(&val) == nil {
		// Case: - FOO: "string".
		if valNode.Style == yaml.DoubleQuotedStyle {
			val = `"` + val + `"`
			return
		}
		// Case: - FOO: n.
		if valNode.Style == 0 && val == "n" {
			val = kconfig.No
			return
		}
		err = fmt.Errorf("bad config format")
		return
	}
	// Case: - FOO: [...].
	propsNode := []yaml.Node{}
	if err = valNode.Decode(&propsNode); err != nil {
		return
	}
	for _, propNode := range propsNode {
		prop := ""
		if err = propNode.Decode(&prop); err != nil {
			return
		}
		if propNode.Style == yaml.DoubleQuotedStyle {
			val = `"` + prop + `"`
		} else if prop == "n" {
			val = kconfig.No
		} else if intVal, err := strconv.ParseUint(prop, 0, 64); err == nil {
			val = fmt.Sprint(intVal)
		} else {
			constraints = append(constraints, prop)
		}
	}
	return
}

type Errors []byte

func (errs *Errors) push(msg string, args ...interface{}) {
	*errs = append(*errs, fmt.Sprintf(msg+"\n", args...)...)
}

func (errs *Errors) err() error {
	if len(*errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", *errs)
}
