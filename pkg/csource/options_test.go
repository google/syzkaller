// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseOptions(t *testing.T) {
	for _, opts := range allOptionsSingle("linux") {
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
			Threaded:      true,
			Collide:       true,
			Repeat:        true,
			Procs:         10,
			Sandbox:       "namespace",
			Fault:         true,
			FaultCall:     1,
			FaultNth:      2,
			EnableTun:     true,
			UseTmpDir:     true,
			EnableCgroups: true,
			EnableNetdev:  true,
			ResetNet:      true,
			HandleSegv:    true,
			Repro:         true,
		},
		`{"threaded":true,"collide":true,"repeat":true,"procs":10,"sandbox":"android_untrusted_app",
		"fault":true,"fault_call":1,"fault_nth":2,"tun":true,"tmpdir":true,"cgroups":true,
		"netdev":true,"resetnet":true,
		"segv":true,"waitrepeat":true,"debug":true,"repro":true}`: {
			Threaded:      true,
			Collide:       true,
			Repeat:        true,
			Procs:         10,
			Sandbox:       "android_untrusted_app",
			Fault:         true,
			FaultCall:     1,
			FaultNth:      2,
			EnableTun:     true,
			UseTmpDir:     true,
			EnableCgroups: true,
			EnableNetdev:  true,
			ResetNet:      true,
			HandleSegv:    true,
			Repro:         true,
		},
		"{Threaded:true Collide:true Repeat:true Procs:1 Sandbox:none Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:      true,
			Collide:       true,
			Repeat:        true,
			Procs:         1,
			Sandbox:       "none",
			Fault:         false,
			FaultCall:     -1,
			FaultNth:      0,
			EnableTun:     true,
			UseTmpDir:     true,
			EnableCgroups: false,
			HandleSegv:    true,
			Repro:         false,
		},
		"{Threaded:true Collide:true Repeat:true Procs:1 Sandbox: Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:      true,
			Collide:       true,
			Repeat:        true,
			Procs:         1,
			Sandbox:       "",
			Fault:         false,
			FaultCall:     -1,
			FaultNth:      0,
			EnableTun:     true,
			UseTmpDir:     true,
			EnableCgroups: false,
			HandleSegv:    true,
			Repro:         false,
		},
		"{Threaded:false Collide:true Repeat:true Procs:1 Sandbox:namespace Fault:false FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true EnableCgroups:true HandleSegv:true WaitRepeat:true Debug:false Repro:false}": {
			Threaded:      false,
			Collide:       true,
			Repeat:        true,
			Procs:         1,
			Sandbox:       "namespace",
			Fault:         false,
			FaultCall:     -1,
			FaultNth:      0,
			EnableTun:     true,
			UseTmpDir:     true,
			EnableCgroups: true,
			HandleSegv:    true,
			Repro:         false,
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
	return opts
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
	return opts
}

func enumerateField(OS string, opt Options, field int) []Options {
	var opts []Options
	s := reflect.ValueOf(&opt).Elem()
	fldName := s.Type().Field(field).Name
	fld := s.Field(field)
	if fldName == "Sandbox" {
		for _, sandbox := range []string{"", "none", "setuid", "namespace", "android_untrusted_app"} {
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
