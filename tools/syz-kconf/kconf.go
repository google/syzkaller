// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-kconf generates Linux kernel configs in dashboard/config/linux.
// See dashboard/config/linux/README.md for details.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

const (
	featOverride = "override"
	featOptional = "optional"
	featAppend   = "append"
	featWeak     = "weak"
	featBaseline = "baseline"
	featClang    = "clang"
	featAndroid  = "android"
	featChromeos = "chromeos"
)

func main() {
	var (
		flagSourceDir = flag.String("sourcedir", "", "sourcedir")
		flagConfig    = flag.String("config", "", "config")
		flagInstance  = flag.String("instance", "", "instance")
	)
	flag.Parse()
	if *flagSourceDir == "" {
		tool.Failf("missing mandatory flag -sourcedir")
	}
	repo, err := vcs.NewRepo(targets.Linux, "", *flagSourceDir, vcs.OptPrecious)
	if err != nil {
		tool.Failf("failed to create repo: %v", err)
	}
	instances, err := parseMainSpec(*flagConfig)
	if err != nil {
		tool.Fail(err)
	}
	if err := checkConfigs(instances); err != nil {
		tool.Fail(err)
	}
	// In order to speed up the process we generate instances that use the same kernel revision in parallel.
	failed := false
	generated := make(map[string]bool)
	for _, inst := range instances {
		// Find the first instance that we did not generate yet.
		if *flagInstance != "" && *flagInstance != inst.Name || generated[inst.Name] {
			continue
		}
		fmt.Printf("git checkout %v %v\n", inst.Kernel.Repo, inst.Kernel.Tag)
		if _, err := repo.SwitchCommit(inst.Kernel.Tag); err != nil {
			if _, err := repo.CheckoutCommit(inst.Kernel.Repo, inst.Kernel.Tag); err != nil {
				tool.Failf("failed to checkout %v/%v: %v", inst.Kernel.Repo, inst.Kernel.Tag, err)
			}
		}
		releaseTag, err := repo.ReleaseTag("HEAD")
		if err != nil {
			tool.Fail(err)
		}
		fmt.Printf("kernel release %v\n", releaseTag)
		// Now generate all instances that use this kernel revision in parallel (each will use own build dir).
		batch := 0
		results := make(chan error)
		for _, inst1 := range instances {
			if *flagInstance != "" && *flagInstance != inst1.Name || generated[inst1.Name] || inst1.Kernel != inst.Kernel {
				continue
			}
			fmt.Printf("generating %v...\n", inst1.Name)
			generated[inst1.Name] = true
			batch++
			ctx := &Context{
				Inst:       inst1,
				ConfigDir:  filepath.Dir(*flagConfig),
				SourceDir:  *flagSourceDir,
				ReleaseTag: releaseTag,
			}
			go func() {
				if err := ctx.generate(); err != nil {
					results <- fmt.Errorf("%v failed:\n%v", ctx.Inst.Name, err)
				}
				results <- nil
			}()
		}
		for i := 0; i < batch; i++ {
			if err := <-results; err != nil {
				fmt.Printf("%v\n", err)
				failed = true
			}
		}
	}
	if failed {
		tool.Failf("some configs failed")
	}
	if len(generated) == 0 {
		tool.Failf("unknown instance name")
	}
}

func checkConfigs(instances []*Instance) error {
	allFeatures := make(Features)
	for _, inst := range instances {
		for feat := range inst.Features {
			allFeatures[feat] = true
		}
	}
	dedup := make(map[string]bool)
	errorString := ""
	for _, inst := range instances {
		for _, cfg := range inst.Configs {
			for _, feat := range cfg.Constraints {
				if feat[0] == '-' {
					feat = feat[1:]
				}
				if allFeatures[feat] || releaseRe.MatchString(feat) {
					continue
				}
				msg := fmt.Sprintf("%v:%v: unknown feature %v", cfg.File, cfg.Line, feat)
				if dedup[msg] {
					continue
				}
				dedup[msg] = true
				errorString += "\n" + msg
			}
		}
	}
	if errorString != "" {
		return errors.New(errorString[1:])
	}
	return nil
}

// Generation context for a single instance.
type Context struct {
	Inst       *Instance
	Target     *targets.Target
	Kconf      *kconfig.KConfig
	ConfigDir  string
	BuildDir   string
	SourceDir  string
	ReleaseTag string
}

func (ctx *Context) generate() error {
	var err error
	if ctx.BuildDir, err = ioutil.TempDir("", "syz-kconf"); err != nil {
		return err
	}
	defer os.RemoveAll(ctx.BuildDir)
	if err := ctx.setTarget(); err != nil {
		return err
	}
	if ctx.Kconf, err = kconfig.Parse(ctx.Target, filepath.Join(ctx.SourceDir, "Kconfig")); err != nil {
		return err
	}
	if err := ctx.setReleaseFeatures(); err != nil {
		return err
	}
	if err := ctx.mrProper(); err != nil {
		return err
	}
	if err := ctx.executeShell(); err != nil {
		return err
	}
	configFile := filepath.Join(ctx.BuildDir, ".config")
	cf, err := kconfig.ParseConfig(configFile)
	if err != nil {
		return err
	}
	if !ctx.Inst.Features[featBaseline] {
		if err := ctx.addUSBConfigs(cf); err != nil {
			return err
		}
	}
	ctx.applyConfigs(cf)
	cf.ModToYes()
	// Set all configs that are not present (actually not present, rather than "is not set") to "is not set".
	// This avoids olddefconfig turning on random things we did not ask for.
	for _, cfg := range ctx.Kconf.Configs {
		if (cfg.Type == kconfig.TypeTristate || cfg.Type == kconfig.TypeBool) && cf.Map[cfg.Name] == nil {
			cf.Set(cfg.Name, kconfig.No)
		}
	}
	original := cf.Serialize()
	if err := osutil.WriteFile(configFile, original); err != nil {
		return fmt.Errorf("failed to write .config file: %v", err)
	}
	// Save what we've got before olddefconfig for debugging purposes, it allows to see if we did not set a config,
	// or olddefconfig removed it. Save as .tmp so that it's not checked-in accidentially.
	outputFile := filepath.Join(ctx.ConfigDir, ctx.Inst.Name+".config")
	outputFileTmp := outputFile + ".tmp"
	if err := osutil.WriteFile(outputFileTmp, original); err != nil {
		return fmt.Errorf("failed to write tmp config file: %v", err)
	}
	if err := ctx.Make("olddefconfig"); err != nil {
		return err
	}
	cf, err = kconfig.ParseConfig(configFile)
	if err != nil {
		return err
	}
	if err := ctx.verifyConfigs(cf); err != nil {
		return fmt.Errorf("%vsaved config before olddefconfig to %v", err, outputFileTmp)
	}
	cf.ModToNo()
	config := []byte(fmt.Sprintf(`# Automatically generated by syz-kconf; DO NOT EDIT.
# Kernel: %v %v

%s
%s
`,
		ctx.Inst.Kernel.Repo, ctx.Inst.Kernel.Tag, cf.Serialize(), ctx.Inst.Verbatim))
	return osutil.WriteFile(outputFile, config)
}

func (ctx *Context) executeShell() error {
	for _, shell := range ctx.Inst.Shell {
		if !ctx.Inst.Features.Match(shell.Constraints) {
			continue
		}
		args := strings.Split(shell.Cmd, " ")
		for i := 1; i < len(args); i++ {
			args[i] = strings.ReplaceAll(args[i], "${BUILDDIR}", ctx.BuildDir)
		}
		if args[0] == "make" {
			if err := ctx.Make(args[1:]...); err != nil {
				return err
			}
			continue
		}
		if _, err := osutil.RunCmd(10*time.Minute, ctx.SourceDir, args[0], args[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *Context) applyConfigs(cf *kconfig.ConfigFile) {
	for _, cfg := range ctx.Inst.Configs {
		if !ctx.Inst.Features.Match(cfg.Constraints) {
			continue
		}
		if cfg.Value != kconfig.No {
			// If this is a choice, first unset all other options.
			// If we leave 2 choice options enabled, the last one will win.
			// It can make sense to move this code to kconfig in some form,
			// it's needed everywhere configs are changed.
			if m := ctx.Kconf.Configs[cfg.Name]; m != nil && m.Parent.Kind == kconfig.MenuChoice {
				for _, choice := range m.Parent.Elems {
					cf.Unset(choice.Name)
				}
			}
		}
		cf.Set(cfg.Name, cfg.Value)
	}
}

func (ctx *Context) verifyConfigs(cf *kconfig.ConfigFile) error {
	errs := new(Errors)
	for _, cfg := range ctx.Inst.Configs {
		act := cf.Value(cfg.Name)
		if act == cfg.Value || cfg.Optional || !ctx.Inst.Features.Match(cfg.Constraints) {
			continue
		}
		if act == kconfig.No {
			errs.push("%v:%v: %v is not present in the final config", cfg.File, cfg.Line, cfg.Name)
		} else if cfg.Value == kconfig.No {
			errs.push("%v:%v: %v is present in the final config", cfg.File, cfg.Line, cfg.Name)
		} else {
			errs.push("%v:%v: %v does not match final config %v vs %v",
				cfg.File, cfg.Line, cfg.Name, cfg.Value, act)
		}
	}
	return errs.err()
}

func (ctx *Context) addUSBConfigs(cf *kconfig.ConfigFile) error {
	prefix := ""
	switch {
	case ctx.Inst.Features[featAndroid]:
		prefix = "android"
	case ctx.Inst.Features[featChromeos]:
		prefix = "chromeos"
	}
	distroConfig := filepath.Join(ctx.ConfigDir, "distros", prefix+"*")
	// Some USB drivers don't depend on any USB related symbols, but rather on a generic symbol
	// for some input subsystem (e.g. HID), so include it as well.
	return ctx.addDependentConfigs(cf, []string{"USB_SUPPORT", "HID"}, distroConfig)
}

func (ctx *Context) addDependentConfigs(dst *kconfig.ConfigFile, include []string, configGlob string) error {
	configFiles, err := filepath.Glob(configGlob)
	if err != nil {
		return err
	}
	includes := func(a []string, b map[string]bool) bool {
		for _, x := range a {
			if b[x] {
				return true
			}
		}
		return false
	}
	selected := make(map[string]bool)
	for _, cfg := range ctx.Kconf.Configs {
		deps := cfg.DependsOn()
		if !includes(include, deps) {
			continue
		}
		selected[cfg.Name] = true
		for dep := range deps {
			selected[dep] = true
		}
	}
	dedup := make(map[string]bool)
	for _, file := range configFiles {
		cf, err := kconfig.ParseConfig(file)
		if err != nil {
			return err
		}
		for _, cfg := range cf.Configs {
			if cfg.Value == kconfig.No || dedup[cfg.Name] || !selected[cfg.Name] {
				continue
			}
			dedup[cfg.Name] = true
			dst.Set(cfg.Name, cfg.Value)
		}
	}
	return nil
}

func (ctx *Context) setTarget() error {
	for _, target := range targets.List[targets.Linux] {
		if ctx.Inst.Features[target.KernelArch] {
			if ctx.Target != nil {
				return fmt.Errorf("arch is set twice")
			}
			ctx.Target = targets.GetEx(targets.Linux, target.Arch, ctx.Inst.Features[featClang])
		}
	}
	if ctx.Target == nil {
		return fmt.Errorf("no arch feature")
	}
	return nil
}

func (ctx *Context) setReleaseFeatures() error {
	tag := ctx.ReleaseTag
	match := releaseRe.FindStringSubmatch(tag)
	if match == nil {
		return fmt.Errorf("bad release tag %q", tag)
	}
	major, err := strconv.ParseInt(match[1], 10, 32)
	if err != nil {
		return fmt.Errorf("bad release tag %q: %v", tag, err)
	}
	minor, err := strconv.ParseInt(match[2], 10, 32)
	if err != nil {
		return fmt.Errorf("bad release tag %q: %v", tag, err)
	}
	for ; major >= 2; major-- {
		for ; minor >= 0; minor-- {
			ctx.Inst.Features[fmt.Sprintf("v%v.%v", major, minor)] = true
		}
		minor = 99
	}
	return nil
}

var releaseRe = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)(?:-rc([0-9]+))?(?:\.([0-9]+))?$`)

func (ctx *Context) mrProper() error {
	// Run 'make mrproper', otherwise out-of-tree build fails.
	// However, it takes unreasonable amount of time,
	// so first check few files and if they are missing hope for best.
	files := []string{
		".config",
		"init/main.o",
		"include/config",
		"include/generated/compile.h",
		"arch/" + ctx.Target.KernelArch + "/include/generated",
	}
	for _, file := range files {
		if osutil.IsExist(filepath.Join(ctx.SourceDir, filepath.FromSlash(file))) {
			goto clean
		}
	}
	return nil
clean:
	buildDir := ctx.BuildDir
	ctx.BuildDir = ctx.SourceDir
	err := ctx.Make("mrproper")
	ctx.BuildDir = buildDir
	return err
}

func (ctx *Context) Make(args ...string) error {
	args = append(args,
		"O="+ctx.BuildDir,
		"ARCH="+ctx.Target.KernelArch,
		"-j", fmt.Sprint(runtime.NumCPU()),
	)
	if ctx.Target.Triple != "" {
		args = append(args, "CROSS_COMPILE="+ctx.Target.Triple+"-")
	}
	if ctx.Target.KernelCompiler != "" {
		args = append(args, "CC="+ctx.Target.KernelCompiler)
	}
	_, err := osutil.RunCmd(10*time.Minute, ctx.SourceDir, "make", args...)
	return err
}
