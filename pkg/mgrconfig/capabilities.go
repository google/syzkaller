// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"reflect"
	"strconv"
	"strings"
)

type BootTestCaps struct {
	CPUVendor string `json:"vendor"`
	Nested    *bool  `json:"nested"`
}

func (caps *BootTestCaps) ToMap() map[string]string {
	m := make(map[string]string)
	if caps == nil {
		return m
	}
	v := reflect.ValueOf(*caps)
	t := reflect.TypeFor[BootTestCaps]()

	for i := range v.NumField() {
		field := v.Field(i)
		fieldType := t.Field(i)

		key := fieldType.Tag.Get("json")
		if key == "" || key == "-" {
			key = fieldType.Name
		} else {
			key, _, _ = strings.Cut(key, ",")
		}

		switch field.Kind() {
		case reflect.String:
			val := field.String()
			if val != "" {
				m[key] = val
			}
		case reflect.Ptr:
			if !field.IsNil() {
				elem := field.Elem()
				if elem.Kind() == reflect.Bool {
					m[key] = strconv.FormatBool(elem.Bool())
				}
			}
		}
	}
	return m
}
