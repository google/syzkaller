// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/google/syzkaller/pkg/osutil"
)

func LoadFile(filename string, cfg interface{}) error {
	if filename == "" {
		return fmt.Errorf("no config file specified")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return LoadData(data, cfg)
}

func LoadData(data []byte, cfg interface{}) error {
	// Remove comment lines starting with #.
	data = regexp.MustCompile(`(^|\n)\s*#[^\n]*`).ReplaceAll(data, nil)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	return nil
}

func SaveFile(filename string, cfg interface{}) error {
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}
