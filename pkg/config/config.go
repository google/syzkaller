// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
)

func Load(filename string, cfg interface{}) error {
	if filename == "" {
		return fmt.Errorf("no config file specified")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	return load(data, cfg)
}

func load(data []byte, cfg interface{}) error {
	if err := checkUnknownFields(data, reflect.ValueOf(cfg).Type()); err != nil {
		return err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	return nil
}

func checkUnknownFields(data []byte, typ reflect.Type) error {
	if typ.Kind() != reflect.Ptr {
		return fmt.Errorf("config type is not pointer to struct")
	}
	typ = typ.Elem()
	if typ.Kind() != reflect.Struct {
		return fmt.Errorf("config type is not pointer to struct")
	}
	fields := make(map[string]bool)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Tag.Get("json") == "-" {
			continue
		}
		fields[strings.ToLower(field.Name)] = true
	}
	f := make(map[string]interface{})
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	for k := range f {
		if !fields[strings.ToLower(k)] {
			return fmt.Errorf("unknown field '%v' in config", k)
		}
	}
	return nil
}
