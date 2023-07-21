// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tool

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

type Flag struct {
	Name  string
	Value string
}

// OptionalFlags produces command line flag value that encapsulates the given flags as optional.
// This is intended for programmatic use only when we invoke older versions of binaries with new unsupported flags.
// Use tool.Init to support optional flags in the binary.
// The format keeps flags reasonably readable ("-optional=foo=bar:baz=123"), not subject to accidental splitting
// into multiple arguments due to spaces and supports bool/non-bool flags.
func OptionalFlags(flags []Flag) string {
	return fmt.Sprintf("-%v=%v", optionalFlag, serializeFlags(flags))
}

func ParseFlags(set *flag.FlagSet, args []string) error {
	flagOptional := set.String(optionalFlag, "", "optional flags for programmatic use only")
	if err := set.Parse(args); err != nil {
		return err
	}
	flags, err := deserializeFlags(*flagOptional)
	if err != nil {
		return err
	}
	for _, f := range flags {
		ff := set.Lookup(f.Name)
		if ff == nil {
			log.Logf(0, "ignoring optional flag %q=%q", f.Name, f.Value)
			continue
		}
		if err := ff.Value.Set(f.Value); err != nil {
			return err
		}
	}
	return nil
}

const optionalFlag = "optional"

func serializeFlags(flags []Flag) string {
	if len(flags) == 0 {
		return ""
	}
	buf := new(bytes.Buffer)
	for _, f := range flags {
		fmt.Fprintf(buf, ":%v=%v", flagEscape(f.Name), flagEscape(f.Value))
	}
	return buf.String()[1:]
}

func deserializeFlags(value string) ([]Flag, error) {
	if value == "" {
		return nil, nil
	}
	var flags []Flag
	for _, arg := range strings.Split(value, ":") {
		eq := strings.IndexByte(arg, '=')
		if eq == -1 {
			return nil, fmt.Errorf("failed to parse flags %q: no eq", value)
		}
		name, err := flagUnescape(arg[:eq])
		if err != nil {
			return nil, fmt.Errorf("failed to parse flags %q: %w", value, err)
		}
		value, err := flagUnescape(arg[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse flags %q: %w", value, err)
		}
		flags = append(flags, Flag{name, value})
	}
	return flags, nil
}

func flagEscape(s string) string {
	buf := new(bytes.Buffer)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch <= 0x20 || ch >= 0x7f || ch == ':' || ch == '=' || ch == '\\' {
			buf.Write([]byte{'\\', 'x'})
			buf.WriteString(hex.EncodeToString([]byte{ch}))
			continue
		}
		buf.WriteByte(ch)
	}
	return buf.String()
}

func flagUnescape(s string) (string, error) {
	buf := new(bytes.Buffer)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch <= 0x20 || ch >= 0x7f || ch == ':' || ch == '=' {
			return "", fmt.Errorf("unescaped char %v", ch)
		}
		if ch == '\\' {
			if i+4 > len(s) || s[i+1] != 'x' {
				return "", fmt.Errorf("truncated escape sequence")
			}
			res, err := hex.DecodeString(s[i+2 : i+4])
			if err != nil {
				return "", err
			}
			buf.WriteByte(res[0])
			i += 3
			continue
		}
		buf.WriteByte(ch)
	}
	return buf.String(), nil
}

// CfgsFlag allows passing a list of configuration files to the same flag and
// provides parsing utilities.
type CfgsFlag []string

// String correctly converts the flag values into a string which is required to
// parse them afterwards.
func (cfgs *CfgsFlag) String() string {
	return fmt.Sprint(*cfgs)
}

// Set is used by flag.Parse to correctly parse the command line arguments.
func (cfgs *CfgsFlag) Set(value string) error {
	if len(*cfgs) > 0 {
		return errors.New("configs flag were already set")
	}
	for _, cfg := range strings.Split(value, ",") {
		cfg = strings.TrimSpace(cfg)
		*cfgs = append(*cfgs, cfg)
	}
	return nil
}
