// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
)

// ConfigFile represents a parsed .config file.
// It should not be modified directly, only by means of calling methods.
// The only exception is Config.Value which may be modified directly.
// Note: config names don't include CONFIG_ prefix, here and in other public interfaces,
// users of this package should never mention CONFIG_.
// Use Yes/Mod/No consts to check for/set config to particular values.
type ConfigFile struct {
	Configs  []*Config
	Map      map[string]*Config // duplicates Configs for convenience
	comments []string
}

type Config struct {
	Name     string
	Value    string
	comments []string
}

const (
	Yes    = "y"
	Mod    = "m"
	No     = "---===[[[is not set]]]===---" // to make it more obvious when some code writes it directly
	prefix = "CONFIG_"
)

// Value returns config value, or No if it's not present at all.
func (cf *ConfigFile) Value(name string) string {
	cfg := cf.Map[name]
	if cfg == nil {
		return No
	}
	return cfg.Value
}

// Set changes config value, or adds it if it's not yet present.
func (cf *ConfigFile) Set(name, val string) {
	cfg := cf.Map[name]
	if cfg == nil {
		cfg = &Config{
			Name:  name,
			Value: val,
		}
		cf.Map[name] = cfg
		cf.Configs = append(cf.Configs, cfg)
	}
	cfg.Value = val
	cfg.comments = append(cfg.comments, cf.comments...)
	cf.comments = nil
}

// Unset sets config value to No, if it's present in the config.
func (cf *ConfigFile) Unset(name string) {
	cfg := cf.Map[name]
	if cfg == nil {
		return
	}
	cfg.Value = No
}

func (cf *ConfigFile) ModToYes() {
	for _, cfg := range cf.Configs {
		if cfg.Value == Mod {
			cfg.Value = Yes
		}
	}
}

func (cf *ConfigFile) ModToNo() {
	for _, cfg := range cf.Configs {
		if cfg.Value == Mod {
			cfg.Value = No
		}
	}
}

func (cf *ConfigFile) Serialize() []byte {
	buf := new(bytes.Buffer)
	for _, cfg := range cf.Configs {
		for _, comment := range cfg.comments {
			fmt.Fprintf(buf, "%v\n", comment)
		}
		if cfg.Value == No {
			fmt.Fprintf(buf, "# %v%v is not set\n", prefix, cfg.Name)
		} else {
			fmt.Fprintf(buf, "%v%v=%v\n", prefix, cfg.Name, cfg.Value)
		}
	}
	for _, comment := range cf.comments {
		fmt.Fprintf(buf, "%v\n", comment)
	}
	return buf.Bytes()
}

func ParseConfig(file string) (*ConfigFile, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open .config file %v: %w", file, err)
	}
	return ParseConfigData(data, file)
}

func ParseConfigData(data []byte, file string) (*ConfigFile, error) {
	cf := &ConfigFile{
		Map: make(map[string]*Config),
	}
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		cf.parseLine(s.Text())
	}
	return cf, nil
}

func (cf *ConfigFile) Clone() *ConfigFile {
	cf1 := &ConfigFile{
		Map:      make(map[string]*Config),
		comments: cf.comments,
	}
	for _, cfg := range cf.Configs {
		cfg1 := new(Config)
		*cfg1 = *cfg
		cf1.Configs = append(cf1.Configs, cfg1)
		cf1.Map[cfg1.Name] = cfg1
	}
	return cf1
}

func (cf *ConfigFile) parseLine(text string) {
	if match := reConfigY.FindStringSubmatch(text); match != nil {
		cf.Set(match[1], match[2])
	} else if match := reConfigN.FindStringSubmatch(text); match != nil {
		cf.Set(match[1], No)
	} else {
		cf.comments = append(cf.comments, text)
	}
}

var (
	reConfigY = regexp.MustCompile(`^` + prefix + `([A-Za-z0-9_]+)=(y|m|(?:-?[0-9]+)|(?:0x[0-9a-fA-F]+)|(?:".*?"))$`)
	reConfigN = regexp.MustCompile(`^# ` + prefix + `([A-Za-z0-9_]+) is not set$`)
)
