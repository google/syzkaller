// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

// Options control various aspects of source generation.
// Dashboard also provides serialized Options along with syzkaller reproducers.
type Options struct {
	Threaded    bool   `json:"threaded,omitempty"`
	Collide     bool   `json:"collide,omitempty"`
	Repeat      bool   `json:"repeat,omitempty"`
	RepeatTimes int    `json:"repeat_times,omitempty"` // if non-0, repeat that many times
	Procs       int    `json:"procs"`
	Sandbox     string `json:"sandbox"`

	Fault     bool `json:"fault,omitempty"` // inject fault into FaultCall/FaultNth
	FaultCall int  `json:"fault_call,omitempty"`
	FaultNth  int  `json:"fault_nth,omitempty"`

	// These options allow for a more fine-tuned control over the generated C code.
	EnableTun        bool `json:"tun,omitempty"`
	EnableNetDev     bool `json:"netdev,omitempty"`
	EnableNetReset   bool `json:"resetnet,omitempty"`
	EnableCgroups    bool `json:"cgroups,omitempty"`
	EnableBinfmtMisc bool `json:"binfmt_misc,omitempty"`
	EnableCloseFds   bool `json:"close_fds"`

	UseTmpDir  bool `json:"tmpdir,omitempty"`
	HandleSegv bool `json:"segv,omitempty"`

	// Generate code for use with repro package to prints log messages,
	// which allows to detect hangs.
	Repro bool `json:"repro,omitempty"`
	Trace bool `json:"trace,omitempty"`
}

// Check checks if the opts combination is valid or not.
// For example, Collide without Threaded is not valid.
// Invalid combinations must not be passed to Write.
func (opts Options) Check(OS string) error {
	switch opts.Sandbox {
	case "", sandboxNone, sandboxNamespace, sandboxSetuid, sandboxAndroidUntrustedApp:
	default:
		return fmt.Errorf("unknown sandbox %v", opts.Sandbox)
	}
	if !opts.Threaded && opts.Collide {
		// Collide requires threaded.
		return errors.New("Collide without Threaded")
	}
	if !opts.Repeat {
		if opts.Procs > 1 {
			// This does not affect generated code.
			return errors.New("Procs>1 without Repeat")
		}
		if opts.EnableNetReset {
			return errors.New("EnableNetReset without Repeat")
		}
		if opts.RepeatTimes > 1 {
			return errors.New("RepeatTimes without Repeat")
		}
	}
	if opts.Sandbox == "" {
		if opts.EnableTun {
			return errors.New("EnableTun without sandbox")
		}
		if opts.EnableNetDev {
			return errors.New("EnableNetDev without sandbox")
		}
		if opts.EnableCgroups {
			return errors.New("EnableCgroups without sandbox")
		}
		if opts.EnableBinfmtMisc {
			return errors.New("EnableBinfmtMisc without sandbox")
		}
	}
	if opts.Sandbox == sandboxNamespace && !opts.UseTmpDir {
		// This is borken and never worked.
		// This tries to create syz-tmp dir in cwd,
		// which will fail if procs>1 and on second run of the program.
		return errors.New("Sandbox=namespace without UseTmpDir")
	}
	if opts.EnableNetReset && (opts.Sandbox == "" || opts.Sandbox == sandboxSetuid) {
		return errors.New("EnableNetReset without sandbox")
	}
	if opts.EnableCgroups && !opts.UseTmpDir {
		return errors.New("EnableCgroups without UseTmpDir")
	}
	return opts.checkLinuxOnly(OS)
}

func (opts Options) checkLinuxOnly(OS string) error {
	if OS == linux {
		return nil
	}
	if opts.EnableTun && !(OS == openbsd || OS == freebsd) {
		return fmt.Errorf("EnableTun is not supported on %v", OS)
	}
	if opts.EnableNetDev {
		return fmt.Errorf("EnableNetDev is not supported on %v", OS)
	}
	if opts.EnableNetReset {
		return fmt.Errorf("EnableNetReset is not supported on %v", OS)
	}
	if opts.EnableCgroups {
		return fmt.Errorf("EnableCgroups is not supported on %v", OS)
	}
	if opts.EnableBinfmtMisc {
		return fmt.Errorf("EnableBinfmtMisc is not supported on %v", OS)
	}
	if opts.EnableCloseFds {
		return fmt.Errorf("EnableCloseFds is not supported on %v", OS)
	}
	if opts.Sandbox == sandboxNamespace ||
		(opts.Sandbox == sandboxSetuid && !(OS == openbsd || OS == freebsd)) ||
		opts.Sandbox == sandboxAndroidUntrustedApp {
		return fmt.Errorf("Sandbox=%v is not supported on %v", opts.Sandbox, OS)
	}
	if opts.Fault {
		return fmt.Errorf("Fault is not supported on %v", OS)
	}
	return nil
}

func DefaultOpts(cfg *mgrconfig.Config) Options {
	opts := Options{
		Threaded:         true,
		Collide:          true,
		Repeat:           true,
		Procs:            cfg.Procs,
		Sandbox:          cfg.Sandbox,
		EnableTun:        true,
		EnableNetDev:     true,
		EnableNetReset:   true,
		EnableCgroups:    true,
		EnableBinfmtMisc: true,
		EnableCloseFds:   true,
		UseTmpDir:        true,
		HandleSegv:       true,
		Repro:            true,
	}
	if cfg.TargetOS != linux {
		opts.EnableTun = false
		opts.EnableNetDev = false
		opts.EnableNetReset = false
		opts.EnableCgroups = false
		opts.EnableBinfmtMisc = false
		opts.EnableCloseFds = false
	}
	if cfg.Sandbox == "" || cfg.Sandbox == "setuid" {
		opts.EnableNetReset = false
	}
	if err := opts.Check(cfg.TargetOS); err != nil {
		panic(fmt.Sprintf("DefaultOpts created bad opts: %v", err))
	}
	return opts
}

func (opts Options) Serialize() []byte {
	data, err := json.Marshal(opts)
	if err != nil {
		panic(err)
	}
	return data
}

func DeserializeOptions(data []byte) (Options, error) {
	var opts Options
	// Before EnableCloseFds was added, close_fds() was always called,
	// so default to true.
	opts.EnableCloseFds = true
	if err := json.Unmarshal(data, &opts); err == nil {
		return opts, nil
	}
	// Support for legacy formats.
	data = bytes.Replace(data, []byte("Sandbox: "), []byte("Sandbox:empty "), -1)
	waitRepeat, debug := false, false
	n, err := fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
	if err == nil {
		if want := 14; n != want {
			return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
		}
		if opts.Sandbox == "empty" {
			opts.Sandbox = ""
		}
		return opts, nil
	}
	n, err = fmt.Sscanf(string(data),
		"{Threaded:%t Collide:%t Repeat:%t Procs:%d Sandbox:%s"+
			" Fault:%t FaultCall:%d FaultNth:%d EnableTun:%t UseTmpDir:%t"+
			" EnableCgroups:%t HandleSegv:%t WaitRepeat:%t Debug:%t Repro:%t}",
		&opts.Threaded, &opts.Collide, &opts.Repeat, &opts.Procs, &opts.Sandbox,
		&opts.Fault, &opts.FaultCall, &opts.FaultNth, &opts.EnableTun, &opts.UseTmpDir,
		&opts.EnableCgroups, &opts.HandleSegv, &waitRepeat, &debug, &opts.Repro)
	if err == nil {
		if want := 15; n != want {
			return opts, fmt.Errorf("failed to parse repro options: got %v fields, want %v", n, want)
		}
		if opts.Sandbox == "empty" {
			opts.Sandbox = ""
		}
		return opts, nil
	}
	return opts, err
}

type Feature struct {
	Description string
	Enabled     bool
}

type Features map[string]Feature

func defaultFeatures(value bool) Features {
	return map[string]Feature{
		"tun":         {"setup and use /dev/tun for packet injection", value},
		"net_dev":     {"setup more network devices for testing", value},
		"net_reset":   {"reset network namespace between programs", value},
		"cgroups":     {"setup cgroups for testing", value},
		"binfmt_misc": {"setup binfmt_misc for testing", value},
		"close_fds":   {"close fds after each program", value},
	}
}

func ParseFeaturesFlags(enable string, disable string, defaultValue bool) (Features, error) {
	if enable == "none" && disable == "none" {
		return defaultFeatures(defaultValue), nil
	}
	if enable != "none" && disable != "none" {
		return nil, fmt.Errorf("can't use -enable and -disable flags at the same time")
	}
	if enable == "all" || disable == "" {
		return defaultFeatures(true), nil
	}
	if disable == "all" || enable == "" {
		return defaultFeatures(false), nil
	}
	var items []string
	var features Features
	if enable != "none" {
		items = strings.Split(enable, ",")
		features = defaultFeatures(false)
	} else {
		items = strings.Split(disable, ",")
		features = defaultFeatures(true)
	}
	for _, item := range items {
		if _, ok := features[item]; !ok {
			return nil, fmt.Errorf("unknown feature specified: %s", item)
		}
		feature := features[item]
		feature.Enabled = (enable != "none")
		features[item] = feature
	}
	return features, nil
}

func PrintAvailableFeaturesFlags() {
	fmt.Printf("Available features for -enable and -disable:\n")
	features := defaultFeatures(false)
	var names []string
	for name := range features {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("  %s - %s\n", name, features[name].Description)
	}
}
