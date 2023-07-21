// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package kconfig implements parsing of the Linux kernel Kconfig and .config files
// and provides some algorithms to work with these files. For Kconfig reference see:
// https://www.kernel.org/doc/html/latest/kbuild/kconfig-language.html
package kconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/syzkaller/sys/targets"
)

// KConfig represents a parsed Kconfig file (including includes).
type KConfig struct {
	Root    *Menu            // mainmenu
	Configs map[string]*Menu // only config/menuconfig entries
}

// Menu represents a single hierarchical menu or config.
type Menu struct {
	Kind   MenuKind   // config/menu/choice/etc
	Type   ConfigType // tristate/bool/string/etc
	Name   string     // name without CONFIG_
	Elems  []*Menu    // sub-elements for menus
	Parent *Menu      // parent menu, non-nil for everythign except for mainmenu

	kconf     *KConfig // back-link to the owning KConfig
	prompts   []prompt
	defaults  []defaultVal
	dependsOn expr
	visibleIf expr
	deps      map[string]bool
	depsOnce  sync.Once
}

type prompt struct {
	text string
	cond expr
}

type defaultVal struct {
	val  expr
	cond expr
}

type (
	MenuKind   int
	ConfigType int
)

const (
	_ MenuKind = iota
	MenuConfig
	MenuGroup
	MenuChoice
	MenuComment
)
const (
	_ ConfigType = iota
	TypeBool
	TypeTristate
	TypeString
	TypeInt
	TypeHex
)

// DependsOn returns all transitive configs this config depends on.
func (m *Menu) DependsOn() map[string]bool {
	m.depsOnce.Do(func() {
		m.deps = make(map[string]bool)
		if m.dependsOn != nil {
			m.dependsOn.collectDeps(m.deps)
		}
		if m.visibleIf != nil {
			m.visibleIf.collectDeps(m.deps)
		}
		var indirect []string
		for cfg := range m.deps {
			dep := m.kconf.Configs[cfg]
			if dep == nil {
				delete(m.deps, cfg)
				continue
			}
			for cfg1 := range dep.DependsOn() {
				indirect = append(indirect, cfg1)
			}
		}
		for _, cfg := range indirect {
			m.deps[cfg] = true
		}
	})
	return m.deps
}

func (m *Menu) Prompt() string {
	// TODO: check prompt conditions, some prompts may be not visible.
	// If all prompts are not visible, then then menu if effectively disabled (at least for user).
	for _, p := range m.prompts {
		return p.text
	}
	return ""
}

type kconfigParser struct {
	*parser
	target    *targets.Target
	includes  []*parser
	stack     []*Menu
	cur       *Menu
	baseDir   string
	helpIdent int
}

func Parse(target *targets.Target, file string) (*KConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open Kconfig file %v: %w", file, err)
	}
	return ParseData(target, data, file)
}

func ParseData(target *targets.Target, data []byte, file string) (*KConfig, error) {
	kp := &kconfigParser{
		parser:  newParser(data, file),
		target:  target,
		baseDir: filepath.Dir(file),
	}
	kp.parseFile()
	if kp.err != nil {
		return nil, kp.err
	}
	if len(kp.stack) == 0 {
		return nil, fmt.Errorf("no mainmenu in config")
	}
	root := kp.stack[0]
	kconf := &KConfig{
		Root:    root,
		Configs: make(map[string]*Menu),
	}
	kconf.walk(root, nil, nil)
	return kconf, nil
}

func (kconf *KConfig) walk(m *Menu, dependsOn, visibleIf expr) {
	m.kconf = kconf
	m.dependsOn = exprAnd(dependsOn, m.dependsOn)
	m.visibleIf = exprAnd(visibleIf, m.visibleIf)
	if m.Kind == MenuConfig {
		kconf.Configs[m.Name] = m
	}
	for _, elem := range m.Elems {
		kconf.walk(elem, m.dependsOn, m.visibleIf)
	}
}

func (kp *kconfigParser) parseFile() {
	for kp.nextLine() {
		kp.parseLine()
		if kp.TryConsume("#") {
			_ = kp.ConsumeLine()
		}
	}
	kp.endCurrent()
}

func (kp *kconfigParser) parseLine() {
	if kp.eol() {
		return
	}
	if kp.helpIdent != 0 {
		if kp.identLevel() >= kp.helpIdent {
			_ = kp.ConsumeLine()
			return
		}
		kp.helpIdent = 0
	}
	if kp.TryConsume("#") {
		_ = kp.ConsumeLine()
		return
	}
	if kp.TryConsume("$") {
		_ = kp.Shell()
		return
	}
	ident := kp.Ident()
	if kp.TryConsume("=") || kp.TryConsume(":=") {
		// Macro definition, see:
		// https://www.kernel.org/doc/html/latest/kbuild/kconfig-macro-language.html
		// We don't use this for anything now.
		kp.ConsumeLine()
		return
	}
	kp.parseMenu(ident)
}

func (kp *kconfigParser) parseMenu(cmd string) {
	switch cmd {
	case "source":
		file, ok := kp.TryQuotedString()
		if !ok {
			file = kp.ConsumeLine()
		}
		kp.includeSource(file)
	case "mainmenu":
		kp.pushCurrent(&Menu{
			Kind:    MenuConfig,
			prompts: []prompt{{text: kp.QuotedString()}},
		})
	case "comment":
		kp.newCurrent(&Menu{
			Kind:    MenuComment,
			prompts: []prompt{{text: kp.QuotedString()}},
		})
	case "menu":
		kp.pushCurrent(&Menu{
			Kind:    MenuGroup,
			prompts: []prompt{{text: kp.QuotedString()}},
		})
	case "if":
		kp.pushCurrent(&Menu{
			Kind:      MenuGroup,
			visibleIf: kp.parseExpr(),
		})
	case "choice":
		kp.pushCurrent(&Menu{
			Kind: MenuChoice,
		})
	case "endmenu", "endif", "endchoice":
		kp.popCurrent()
	case "config", "menuconfig":
		kp.newCurrent(&Menu{
			Kind: MenuConfig,
			Name: kp.Ident(),
		})
	default:
		kp.parseConfigType(cmd)
	}
}

func (kp *kconfigParser) parseConfigType(typ string) {
	cur := kp.current()
	switch typ {
	case "tristate":
		cur.Type = TypeTristate
		kp.tryParsePrompt()
	case "def_tristate":
		cur.Type = TypeTristate
		kp.parseDefaultValue()
	case "bool":
		cur.Type = TypeBool
		kp.tryParsePrompt()
	case "def_bool":
		cur.Type = TypeBool
		kp.parseDefaultValue()
	case "int":
		cur.Type = TypeInt
		kp.tryParsePrompt()
	case "def_int":
		cur.Type = TypeInt
		kp.parseDefaultValue()
	case "hex":
		cur.Type = TypeHex
		kp.tryParsePrompt()
	case "def_hex":
		cur.Type = TypeHex
		kp.parseDefaultValue()
	case "string":
		cur.Type = TypeString
		kp.tryParsePrompt()
	case "def_string":
		cur.Type = TypeString
		kp.parseDefaultValue()
	default:
		kp.parseProperty(typ)
	}
}

func (kp *kconfigParser) parseProperty(prop string) {
	cur := kp.current()
	switch prop {
	case "prompt":
		kp.tryParsePrompt()
	case "depends":
		kp.MustConsume("on")
		cur.dependsOn = exprAnd(cur.dependsOn, kp.parseExpr())
	case "visible":
		kp.MustConsume("if")
		cur.visibleIf = exprAnd(cur.visibleIf, kp.parseExpr())
	case "select", "imply":
		_ = kp.Ident()
		if kp.TryConsume("if") {
			_ = kp.parseExpr()
		}
	case "option":
		// It can be 'option foo', or 'option bar="BAZ"'.
		kp.ConsumeLine()
	case "modules":
	case "optional":
	case "default":
		kp.parseDefaultValue()
	case "range":
		_, _ = kp.parseExpr(), kp.parseExpr() // from, to
		if kp.TryConsume("if") {
			_ = kp.parseExpr()
		}
	case "help", "---help---":
		// Help rules are tricky: end of help is identified by smaller indentation level
		// as would be rendered on a terminal with 8-column tabs setup, minus empty lines.
		for kp.nextLine() {
			if kp.eol() {
				continue
			}
			kp.helpIdent = kp.identLevel()
			kp.ConsumeLine()
			break
		}
	default:
		kp.failf("unknown line")
	}
}

func (kp *kconfigParser) includeSource(file string) {
	kp.newCurrent(nil)
	file = kp.expandString(file)
	file = filepath.Join(kp.baseDir, file)
	data, err := os.ReadFile(file)
	if err != nil {
		kp.failf("%v", err)
		return
	}
	kp.includes = append(kp.includes, kp.parser)
	kp.parser = newParser(data, file)
	kp.parseFile()
	err = kp.err
	kp.parser = kp.includes[len(kp.includes)-1]
	kp.includes = kp.includes[:len(kp.includes)-1]
	if kp.err == nil {
		kp.err = err
	}
}

func (kp *kconfigParser) pushCurrent(m *Menu) {
	kp.endCurrent()
	kp.cur = m
	kp.stack = append(kp.stack, m)
}

func (kp *kconfigParser) popCurrent() {
	kp.endCurrent()
	if len(kp.stack) < 2 {
		kp.failf("unbalanced endmenu")
		return
	}
	last := kp.stack[len(kp.stack)-1]
	kp.stack = kp.stack[:len(kp.stack)-1]
	top := kp.stack[len(kp.stack)-1]
	last.Parent = top
	top.Elems = append(top.Elems, last)
}

func (kp *kconfigParser) newCurrent(m *Menu) {
	kp.endCurrent()
	kp.cur = m
}

func (kp *kconfigParser) current() *Menu {
	if kp.cur == nil {
		kp.failf("config property outside of config")
		return &Menu{}
	}
	return kp.cur
}

func (kp *kconfigParser) endCurrent() {
	if kp.cur == nil {
		return
	}
	if len(kp.stack) == 0 {
		kp.failf("unbalanced endmenu")
		return
	}
	top := kp.stack[len(kp.stack)-1]
	if top != kp.cur {
		kp.cur.Parent = top
		top.Elems = append(top.Elems, kp.cur)
	}
	kp.cur = nil
}

func (kp *kconfigParser) tryParsePrompt() {
	if str, ok := kp.TryQuotedString(); ok {
		prompt := prompt{
			text: str,
		}
		if kp.TryConsume("if") {
			prompt.cond = kp.parseExpr()
		}
		kp.current().prompts = append(kp.current().prompts, prompt)
	}
}

func (kp *kconfigParser) parseDefaultValue() {
	def := defaultVal{val: kp.parseExpr()}
	if kp.TryConsume("if") {
		def.cond = kp.parseExpr()
	}
	kp.current().defaults = append(kp.current().defaults, def)
}

func (kp *kconfigParser) expandString(str string) string {
	str = strings.Replace(str, "$(SRCARCH)", kp.target.KernelHeaderArch, -1)
	str = strings.Replace(str, "$SRCARCH", kp.target.KernelHeaderArch, -1)
	str = strings.Replace(str, "$(KCONFIG_EXT_PREFIX)", "", -1)
	return str
}
