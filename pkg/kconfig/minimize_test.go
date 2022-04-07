// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/sys/targets"
)

func TestMinimize(t *testing.T) {
	const (
		kconfig = `
mainmenu "test"
config A
config B
config C
config D
config I
config S

menuconfig HAMRADIO
	depends on NET && !S390
	bool "Amateur Radio support"

config AX25
	tristate "Amateur Radio AX.25 Level 2 protocol"
	depends on HAMRADIO

config ROSE
	tristate "Amateur Radio X.25 PLP (Rose)"
	depends on AX25
`
		baseConfig = `
CONFIG_A=y
CONFIG_I=1
`
		fullConfig = `
CONFIG_A=y
CONFIG_B=y
CONFIG_C=y
CONFIG_D=y
CONFIG_I=42
CONFIG_S="foo"
CONFIG_HAMRADIO=y
CONFIG_AX25=y
CONFIG_ROSE=y
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
CONFIG_I=42
CONFIG_S="foo"
CONFIG_C=y
`,
		},
		{
			pred: func(cf *ConfigFile) (bool, error) {
				return cf.Value("HAMRADIO") == Yes && cf.Value("AX25") == Yes && cf.Value("ROSE") == Yes, nil
			},
			result: `
CONFIG_A=y
CONFIG_I=42
CONFIG_S="foo"
CONFIG_AX25=y
CONFIG_HAMRADIO=y
CONFIG_ROSE=y
`,
		},
	}
	kconf, err := ParseData(targets.Get("linux", "amd64"), []byte(kconfig), "kconf")
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
			res, err := kconf.Minimize(base, full, test.pred, &debugtracer.TestTracer{T: t})
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
