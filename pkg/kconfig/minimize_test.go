// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMinimize(t *testing.T) {
	const (
		kconfig = `
mainmenu "test"
config A
config B
config C
config D
`

		baseConfig = `
CONFIG_A=y
`
		fullConfig = `
CONFIG_A=y
CONFIG_B=y
CONFIG_C=y
CONFIG_D=y
`
	)
	type Test struct {
		pred   func(*ConfigFile) (bool, error)
		result string
	}
	tests := []Test{
		{
			pred: func(cf *ConfigFile) (bool, error) {
				return true, nil
			},
			result: baseConfig,
		},
		{
			pred: func(cf *ConfigFile) (bool, error) {
				return false, nil
			},
			result: fullConfig,
		},
		{
			pred: func(cf *ConfigFile) (bool, error) {
				return cf.Value("C") != No, nil
			},
			result: `
CONFIG_A=y
CONFIG_C=y
`,
		},
	}
	kconf, err := ParseData([]byte(kconfig), "kconf")
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseConfigData([]byte(baseConfig), "base")
	if err != nil {
		t.Fatal(err)
	}
	full, err := ParseConfigData([]byte(fullConfig), "full")
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			trace := new(bytes.Buffer)
			res, err := kconf.Minimize(base, full, test.pred, trace)
			t.Log(trace.String())
			if err != nil {
				t.Fatal(err)
			}
			result := string(res.Serialize())
			if result != test.result {
				t.Fatalf("got:\n%v\n\nwant:\n%s", result, test.result)
			}
		})
	}
}
