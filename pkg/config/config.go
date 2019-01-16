// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
)

func LoadFile(filename string, cfg interface{}) error {
	if filename == "" {
		return fmt.Errorf("no config file specified")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}
	return LoadData(data, cfg)
}

func LoadData(data []byte, cfg interface{}) error {
	if err := checkUnknownFields(data, reflect.ValueOf(cfg).Type()); err != nil {
		return err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	return nil
}

func SaveFile(filename string, cfg interface{}) error {
	data, err := SaveData(cfg)
	if err != nil {
		return err
	}
	return osutil.WriteFile(filename, data)
}

func SaveData(cfg interface{}) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "\t")
}

func checkUnknownFields(data []byte, typ reflect.Type) error {
	if typ.Kind() != reflect.Ptr || typ.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config type is not pointer to struct")
	}
	return checkUnknownFieldsRec(data, "", typ)
}

func checkUnknownFieldsRec(data []byte, prefix string, typ reflect.Type) error {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return fmt.Errorf("config type is not pointer to struct")
	}
	fields := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		tag = strings.TrimSuffix(tag, ",omitempty")
		if tag == "-" {
			continue
		}
		name := strings.ToLower(field.Name)
		if tag != "" {
			if tag != strings.ToLower(tag) {
				return fmt.Errorf("json tag on '%v%v' should be lower-case", prefix, name)
			}
			name = tag
		}
		fields[name] = field.Type
	}
	f := make(map[string]interface{})
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}
	for k, v := range f {
		field, ok := fields[strings.ToLower(k)]
		if !ok {
			return fmt.Errorf("unknown field '%v%v' in config", prefix, k)
		}
		if v != nil && field.Kind() == reflect.Slice &&
			(field.PkgPath() != "encoding/json" || field.Name() != "RawMessage") {
			vv := reflect.ValueOf(v)
			if vv.Type().Kind() != reflect.Slice {
				return fmt.Errorf("bad json array type '%v%v'", prefix, k)
			}
			for i := 0; i < vv.Len(); i++ {
				e := vv.Index(i).Interface()
				prefix1 := fmt.Sprintf("%v%v[%v].", prefix, k, i)
				if err := checkUnknownFieldsStruct(e, prefix1, field.Elem()); err != nil {
					return err
				}
			}
		}
		if err := checkUnknownFieldsStruct(v, prefix+k+".", field); err != nil {
			return err
		}
	}
	return nil
}

func checkUnknownFieldsStruct(val interface{}, prefix string, typ reflect.Type) error {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	if typ.PkgPath() == "time" && typ.Name() == "Time" {
		return nil
	}
	inner, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("failed to marshal inner struct %q: %v", prefix, err)
	}
	return checkUnknownFieldsRec(inner, prefix, typ)
}
