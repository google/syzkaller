// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package config handles reading, parsing, and merging JSON configuration files.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
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

func LoadData(data []byte, cfg any) error {
	// Remove comment lines starting with #.
	data = regexp.MustCompile(`(^|\n)\s*#[^\n]*`).ReplaceAll(data, nil)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	return nil
}

func SaveFile(filename string, cfg any) error {
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	// Configs may contain secrets (e.g. dashboard_key/hub_key in manager configs),
	// so don't make them readable by other users (incl. the sandbox user).
	// Write to a temp file and rename it, so that a crash can't leave a truncated config behind,
	// and so that an already existing 0644 config is replaced instead of truncated in place.
	// We can't use os.CreateTemp b/c it may be on a different mount, and Rename can't move across mounts.
	tmpFile := filename + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		return err
	}
	return nil
}
