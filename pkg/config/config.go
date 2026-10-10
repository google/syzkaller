// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package config handles reading, parsing, and merging JSON configuration files.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"unicode/utf8"

	"github.com/google/syzkaller/pkg/osutil"
)

func LoadFile(filename string, cfg any) error {
	if filename == "" {
		return fmt.Errorf("no config file specified")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return LoadData(data, cfg)
}

var commentRe = regexp.MustCompile(`(^|\n)\s*#[^\n]*`)

func LoadData(data []byte, cfg any) error {
	// Blank out comment lines starting with # instead of removing them,
	// so that error offsets still match the positions in the original data.
	data = commentRe.ReplaceAllFunc(data, func(comment []byte) []byte {
		blank := make([]byte, len(comment))
		for i, c := range comment {
			if c == '\n' {
				blank[i] = c
			} else {
				blank[i] = ' '
			}
		}
		return blank
	})
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		if syntaxErr, ok := errors.AsType[*json.SyntaxError](err); ok {
			line, col := offsetToLineCol(data, syntaxErr.Offset)
			return fmt.Errorf("failed to parse config file: %w at line %v, column %v", err, line, col)
		}
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	return nil
}

// offsetToLineCol converts a json.SyntaxError offset into 1-based line and column numbers
// of the offending character. The offset points right after the character.
func offsetToLineCol(data []byte, offset int64) (int, int) {
	prefix := data[:min(max(offset-1, 0), int64(len(data)))]
	line := bytes.Count(prefix, []byte{'\n'}) + 1
	col := utf8.RuneCount(prefix[bytes.LastIndexByte(prefix, '\n')+1:]) + 1
	return line, col
}

func SaveFile(filename string, cfg any) error {
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}
