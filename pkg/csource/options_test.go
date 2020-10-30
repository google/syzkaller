// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/syzkaller/sys/targets"
)

func TestParseOptions(t *testing.T) {
	for _, opts := range allOptionsSingle(targets.Linux) {
		data := opts.Serialize()
		got, err := DeserializeOptions(data)
		if err != nil {
			t.Fatalf("failed to deserialize %q: %v", data, err)
		}
		if !reflect.DeepEqual(got, opts) {
			t.Fatalf("opts changed, got:\n%+v\nwant:\n%+v", got, opts)
		}
	}
}

func TestParseOptionsCanned(t *testing.T) {
	// Dashboard stores csource options with syzkaller reproducers,
	// so we need to be able to parse old formats.
	// nolint: lll
	canned := map[string]Options{
		`{"threaded":true,"collide":true,"repeat":true,"procs":10,"sandbox":"namespace",
		"fault":true,"fault_call":1,"fault_nth":2,"tun":true,"tmpdir":true,"cgroups":true,
		"netdev":true,"resetnet":true,
		"segv":true,"waitrepeat":true,"debug":true,"repro":true}`: {
			Threaded:     true,
			Collide:      true,
			Repeat:       true,
			Procs:        10,
			Sandbox:      "namespace",
			Fault:        true,
			FaultCall:    1,
			FaultNth:     2,
			NetInjection: true,
			NetDevices:   true,
			NetReset:     true,
			Cgroups:      true,
			BinfmtMisc:   false,
			CloseFDs:     true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        true,
		},
		`{"threaded":true,"collide":true,"repeat":true,"procs":10,"sandbox":"android",
		"fault":true,"fault_call":1,"fault_nth":2,"tun":true,"tmpdir":true,"cgroups":true,
		"netdev":true,"resetnet":true,
		"segv":true,"waitrepeat":true,"debug":true,"repro":true}`: {
			Threaded:     true,
			Collide:      true,
			Repeat:       true,
			Procs:        10,
			Sandbox:      "android",
			Fault:        true,
			FaultCall:    1,
			FaultNth:     2,
			NetInjection: true,
			NetDevices:   true,
			NetReset:     true,
			Cgroups:      true,
			BinfmtMisc:   false,
			CloseFDs:     true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        true,
		},
		"{Threaded:true Collide:true Repeat:true Procs:1 Sandbox:none Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:     true,
			Collide:      true,
			Repeat:       true,
			Procs:        1,
			Sandbox:      "none",
			Fault:        false,
			FaultCall:    -1,
			FaultNth:     0,
			NetInjection: true,
			Cgroups:      false,
			BinfmtMisc:   false,
			CloseFDs:     true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        false,
		},
		"{Threaded:true Collide:true Repeat:true Procs:1 Sandbox: Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:     true,
			Collide:      true,
			Repeat:       true,
			Procs:        1,
			Sandbox:      "",
			Fault:        false,
			FaultCall:    -1,
			FaultNth:     0,
			NetInjection: true,
			Cgroups:      false,
			BinfmtMisc:   false,
			CloseFDs:     true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        false,
		},
		"{Threaded:false Collide:true Repeat:true Procs:1 Sandbox:namespace Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true EnableCgroups:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:     false,
			Collide:      true,
			Repeat:       true,
			Procs:        1,
			Sandbox:      "namespace",
			Fault:        false,
			FaultCall:    -1,
			FaultNth:     0,
			NetInjection: true,
			Cgroups:      true,
			BinfmtMisc:   false,
			CloseFDs:     true,
			UseTmpDir:    true,
			HandleSegv:   true,
			Repro:        false,
		},
	}
	for data, want := range canned {
		got, err := DeserializeOptions([]byte(data))
		if err != nil {
			t.Fatalf("failed to deserialize %q: %v", data, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("deserialize %q\ngot:\n%+v\nwant:\n%+v", data, got, want)
		}
	}
}

func allOptionsSingle(OS string) []Options {
	var opts []Options
	fields := reflect.TypeOf(Options{}).NumField()
	for i := 0; i < fields; i++ {
		// Because of constraints on options, we need some defaults
		// (e.g. no collide without threaded).
		opt := Options{
			Threaded:  true,
			Repeat:    true,
			Sandbox:   "none",
			UseTmpDir: true,
		}
		opts = append(opts, enumerateField(OS, opt, i)...)
	}
	return dedup(opts)
}

func allOptionsPermutations(OS string) []Options {
	opts := []Options{{}}
	fields := reflect.TypeOf(Options{}).NumField()
	for i := 0; i < fields; i++ {
		var newOpts []Options
		for _, opt := range opts {
			newOpts = append(newOpts, enumerateField(OS, opt, i)...)
		}
		opts = newOpts
	}
	return dedup(opts)
}

func dedup(opts []Options) []Options {
	pos := 0
	dedup := make(map[Options]bool)
	for _, opt := range opts {
		if dedup[opt] {
			continue
		}
		dedup[opt] = true
		opts[pos] = opt
		pos++
	}
	return opts[:pos]
}

func enumerateField(OS string, opt Options, field int) []Options {
	var opts []Options
	s := reflect.ValueOf(&opt).Elem()
	fldName := s.Type().Field(field).Name
	fld := s.Field(field)
	if fldName == "Sandbox" {
		for _, sandbox := range []string{"", "none", "setuid", "namespace", "android"} {
			fld.SetString(sandbox)
			opts = append(opts, opt)
		}
	} else if fldName == "Procs" {
		for _, procs := range []int64{1, 4} {
			fld.SetInt(procs)
			opts = append(opts, opt)
		}
	} else if fldName == "RepeatTimes" {
		for _, times := range []int64{0, 10} {
			fld.SetInt(times)
			opts = append(opts, opt)
		}
	} else if fldName == "FaultCall" {
		opts = append(opts, opt)
	} else if fldName == "FaultNth" {
		opts = append(opts, opt)
	} else if fld.Kind() == reflect.Bool {
		for _, v := range []bool{false, true} {
			fld.SetBool(v)
			opts = append(opts, opt)
		}
	} else {
		panic(fmt.Sprintf("field '%v' is not boolean", fldName))
	}
	var checked []Options
	for _, opt := range opts {
		if err := opt.Check(OS); err == nil {
			checked = append(checked, opt)
		}
	}
	return checked
}

func TestParseFeaturesFlags(t *testing.T) {
	tests := []struct {
		Enable   string
		Disable  string
		Default  bool
		Features map[string]bool
	}{
		{"none", "none", true, map[string]bool{
			"tun":         true,
			"net_dev":     true,
			"net_reset":   true,
			"cgroups":     true,
			"binfmt_misc": true,
			"close_fds":   true,
			"devlink_pci": true,
			"usb":         true,
			"vhci":        true,
			"wifi":        true,
			"sysctl":      true,
		}},
		{"none", "none", false, map[string]bool{}},
		{"all", "none", true, map[string]bool{
			"tun":         true,
			"net_dev":     true,
			"net_reset":   true,
			"cgroups":     true,
			"binfmt_misc": true,
			"close_fds":   true,
			"devlink_pci": true,
			"usb":         true,
			"vhci":        true,
			"wifi":        true,
			"sysctl":      true,
		}},
		{"", "none", true, map[string]bool{}},
		{"none", "all", true, map[string]bool{}},
		{"none", "", true, map[string]bool{
			"tun":         true,
			"net_dev":     true,
			"net_reset":   true,
			"cgroups":     true,
			"binfmt_misc": true,
			"close_fds":   true,
			"devlink_pci": true,
			"usb":         true,
			"vhci":        true,
			"wifi":        true,
			"sysctl":      true,
		}},
		{"tun,net_dev", "none", true, map[string]bool{
			"tun":     true,
			"net_dev": true,
		}},
		{"none", "cgroups,net_dev", true, map[string]bool{
			"tun":         true,
			"net_reset":   true,
			"binfmt_misc": true,
			"close_fds":   true,
			"devlink_pci": true,
			"usb":         true,
			"vhci":        true,
			"wifi":        true,
			"sysctl":      true,
		}},
		{"close_fds", "none", true, map[string]bool{
			"close_fds": true,
		}},
	}
	for i, test := range tests {
		features, err := ParseFeaturesFlags(test.Enable, test.Disable, test.Default)
		if err != nil {
			t.Fatalf("failed to parse features flags: %v", err)
		}
		for name, feature := range features {
			if feature.Enabled != test.Features[name] {
				t.Fatalf("test #%v: invalid value for feature flag %s: got %v, want %v",
					i, name, feature.Enabled, test.Features[name])
			}
		}
	}
}
