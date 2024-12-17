// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type linux struct {
	*git
	vmType string
}

var (
	_ Bisecter        = new(linux)
	_ ConfigMinimizer = new(linux)
)

func newLinux(dir string, opts []RepoOpt, vmType string) *linux {
	ignoreCC := map[string]bool{
		"stable@vger.kernel.org": true,
	}

	return &linux{
		git:    newGit(dir, ignoreCC, opts),
		vmType: vmType,
	}
}

func (ctx *linux) PreviousReleaseTags(commit, compilerType string) ([]string, error) {
	tags, err := ctx.git.previousReleaseTags(commit, false, false, false)
	if err != nil {
		return nil, err
	}

	cutoff := ""
	if compilerType == "gcc" {
		// Initially we tried to stop at 3.8 because:
		// v3.8 does not work with modern perl, and as we go further in history
		// make stops to work, then binutils, glibc, etc. So we stop at v3.8.
		// Up to that point we only need an ancient gcc.
		//
		// But kernels don't boot starting from 4.0 and back.
		// That was fixed by 99124e4db5b7b70daeaaf1d88a6a8078a0004c6e,
		// and it can be cherry-picked into 3.14..4.0 but it conflicts for 3.13 and older.
		//
		// But starting from 4.0 our user-space binaries start crashing with
		// assorted errors which suggests process memory corruption by kernel.
		//
		// We used to use 4.1 as the oldest tested release (it works in general).
		// However, there is correlation between how far back we go and probability
		// of getting correct result (see #1532). So we then stopped at 4.6.
		// 4.6 is somewhat arbitrary, we've seen lots of wrong results in 4.5..4.6 range,
		// but there is definitive reason for 4.6. Most likely later we want to bump it
		// even more (as new releases are produced). Next good candidate may be 4.11
		// because then we won't need gcc 5.5.
		//
		// TODO: The buildroot images deployed after #2820 can only boot v4.19+ kernels.
		// This has caused lots of bad bisection results, see #3224. We either need a new
		// universal image or a kernel version dependant image selection.
		cutoff = "v4.18"
	} else if compilerType == "clang" {
		// v5.3 was the first release with solid clang support, however I was able to
		// compile v5.1..v5.3 using a newer defconfig + make oldconfig. Everything older
		// would require further cherry-picks.
		cutoff = "v5.2"
	}

	for i, tag := range tags {
		if tag == cutoff {
			tags = tags[:i]
			break
		}
	}
	return tags, nil
}

func gitParseReleaseTags(output []byte, includeRC bool) []string {
	var tags []string
	for _, tag := range bytes.Split(output, []byte{'\n'}) {
		if gitReleaseTagToInt(string(tag), includeRC) != 0 {
			tags = append(tags, string(tag))
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		return gitReleaseTagToInt(tags[i], includeRC) > gitReleaseTagToInt(tags[j], includeRC)
	})
	return tags
}

func gitReleaseTagToInt(tag string, includeRC bool) uint64 {
	v1, v2, rc, v3 := ParseReleaseTag(tag)
	if v1 < 0 {
		return 0
	}
	if v3 < 0 {
		v3 = 0
	}
	if rc >= 0 {
		if !includeRC {
			return 0
		}
	} else {
		rc = 999
	}
	return uint64(v1)*1e9 + uint64(v2)*1e6 + uint64(rc)*1e3 + uint64(v3)
}

func (ctx *linux) EnvForCommit(
	defaultCompiler, compilerType, binDir, commit string, kernelConfig []byte,
	backports []BackportCommit,
) (*BisectEnv, error) {
	tagList, err := ctx.previousReleaseTags(commit, true, false, false)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool)
	for _, tag := range tagList {
		tags[tag] = true
	}
	cf, err := kconfig.ParseConfigData(kernelConfig, "config")
	if err != nil {
		return nil, err
	}
	setLinuxTagConfigs(cf, tags)

	compiler := ""
	if compilerType == "gcc" {
		compiler = linuxGCCPath(tags, binDir, defaultCompiler)
	} else if compilerType == "clang" {
		compiler = linuxClangPath(tags, binDir, defaultCompiler)
	} else {
		return nil, fmt.Errorf("unsupported bisect compiler: %v", compilerType)
	}

	env := &BisectEnv{
		Compiler:     compiler,
		KernelConfig: cf.Serialize(),
	}
	err = linuxFixBackports(ctx.git, backports...)
	if err != nil {
		return nil, fmt.Errorf("failed to cherry pick fixes: %w", err)
	}
	return env, nil
}

func linuxClangPath(tags map[string]bool, binDir, defaultCompiler string) string {
	version := ""
	switch {
	case tags["v5.9"]:
		// Verified to work with 14.0.6.
		return defaultCompiler
	default:
		// everything before v5.3 might not work great
		// everything before v5.1 does not work
		version = "9.0.1"
	}
	return filepath.Join(binDir, "llvm-"+version, "bin", "clang")
}

func linuxGCCPath(tags map[string]bool, binDir, defaultCompiler string) string {
	version := ""
	switch {
	case tags["v5.16"]:
		// Verified to work with 15.0.7.
		return defaultCompiler
	case tags["v5.9"]:
		version = "10.1.0"
	case tags["v4.12"]:
		version = "8.1.0"
	case tags["v4.11"]:
		version = "7.3.0"
	default:
		version = "5.5.0"
	}
	return filepath.Join(binDir, "gcc-"+version, "bin", "gcc")
}

func (ctx *linux) PrepareBisect() error {
	if ctx.vmType != targets.GVisor {
		// Some linux repos we fuzz don't import the upstream release git tags. We need tags
		// to decide which compiler versions to use. Let's fetch upstream for its tags.
		err := ctx.git.fetchRemote("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", "")
		if err != nil {
			return fmt.Errorf("fetching upstream linux failed: %w", err)
		}
	}
	return nil
}

func (ctx *linux) Bisect(bad, good string, dt debugtracer.DebugTracer, pred func() (BisectResult,
	error)) ([]*Commit, error) {
	commits, err := ctx.git.Bisect(bad, good, dt, pred)
	if len(commits) == 1 {
		ctx.addMaintainers(commits[0])
	}
	return commits, err
}

func (ctx *linux) addMaintainers(com *Commit) {
	if len(com.Recipients) > 2 {
		return
	}
	mtrs := ctx.getMaintainers(com.Hash, false)
	if len(mtrs) < 3 {
		mtrs = ctx.getMaintainers(com.Hash, true)
	}
	com.Recipients = append(com.Recipients, mtrs...)
	sort.Sort(com.Recipients)
}

func (ctx *linux) getMaintainers(hash string, blame bool) Recipients {
	// See #1441 re --git-min-percent.
	args := "git show " + hash + " | " +
		filepath.FromSlash("scripts/get_maintainer.pl") +
		" --git-min-percent=20"
	if blame {
		args += " --git-blame"
	}
	output, err := osutil.RunCmd(time.Minute, ctx.git.Dir, "bash", "-c", args)
	if err != nil {
		return nil
	}
	return ParseMaintainersLinux(output)
}

func ParseMaintainersLinux(text []byte) Recipients {
	lines := strings.Split(string(text), "\n")
	reRole := regexp.MustCompile(` \([^)]+\)$`)
	var mtrs Recipients
	// LMKL is To by default, but it changes to Cc if there's also a subsystem list.
	lkmlType := To
	foundLkml := false
	for _, line := range lines {
		role := reRole.FindString(line)
		address := strings.Replace(line, role, "", 1)
		addr, err := mail.ParseAddress(address)
		if err != nil {
			continue
		}
		var roleType RecipientType
		if addr.Address == "linux-kernel@vger.kernel.org" {
			foundLkml = true
			continue
		} else if strings.Contains(role, "list") {
			lkmlType = Cc
			roleType = To
		} else if strings.Contains(role, "maintainer") || strings.Contains(role, "supporter") {
			roleType = To
		} else {
			roleType = Cc // Reviewer or other role; default to Cc.
		}
		mtrs = append(mtrs, RecipientInfo{*addr, roleType})
	}
	if foundLkml {
		mtrs = append(mtrs, RecipientInfo{mail.Address{Address: "linux-kernel@vger.kernel.org"}, lkmlType})
	}
	sort.Sort(mtrs)
	return mtrs
}

var ErrBadKconfig = errors.New("failed to parse Kconfig")

const configBisectTag = "# Minimized by syzkaller"

// Minimize() attempts to drop Linux kernel configs that are unnecessary(*) for bug reproduction.
// 1. Remove sanitizers that are not needed to trigger the target class of bugs.
// 2. Disable unrelated kernel subsystems. This is done by bisecting config changes between
// `original` and `baseline`.
// (*) After an unnecessary config is deleted, we still have pred() == BisectBad.
func (ctx *linux) Minimize(target *targets.Target, original, baseline []byte, types []crash.Type,
	dt debugtracer.DebugTracer, pred func(test []byte) (BisectResult, error)) ([]byte, error) {
	if bytes.HasPrefix(original, []byte(configBisectTag)) {
		dt.Log("# configuration already minimized\n")
		return original, nil
	}
	kconf, err := kconfig.Parse(target, filepath.Join(ctx.git.Dir, "Kconfig"))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadKconfig, err)
	}
	config, err := kconfig.ParseConfigData(original, "original")
	if err != nil {
		return nil, err
	}
	minimizeCtx := &minimizeLinuxCtx{
		kconf:  kconf,
		config: config,
		pred: func(cfg *kconfig.ConfigFile) (bool, error) {
			res, err := pred(serialize(cfg))
			return res == BisectBad, err
		},
		transform: func(cfg *kconfig.ConfigFile) {
			setLinuxTagConfigs(cfg, nil)
		},
		DebugTracer: dt,
	}
	if len(types) > 0 {
		// Technically, as almost all sanitizers are Yes/No config options, we could have
		// achieved this minimization simply by disabling them all in the baseline config.
		// However, we are now trying to make the most out of the few config minimization
		// iterations we're ready to make do during the bisection process.
		// Since it's possible to quite reliably determine the needed and unneeded sanitizers
		// just by looking at crash reports, let's prefer a more complicated logic over worse
		// bisection results.
		// Once we start doing proper config minimizations for every reproducer, we can delete
		// most of the related code.
		err := minimizeCtx.dropInstrumentation(types)
		if err != nil {
			return nil, err
		}
	}
	if len(baseline) > 0 {
		baselineConfig, err := kconfig.ParseConfigData(baseline, "baseline")
		// If we fail to parse the baseline config proceed with original one as baseline config
		// is an optional parameter.
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBadKconfig, err)
		}
		err = minimizeCtx.minimizeAgainst(baselineConfig)
		if err != nil {
			return nil, err
		}
	}
	return minimizeCtx.getConfig(), nil
}

func serialize(cf *kconfig.ConfigFile) []byte {
	return []byte(fmt.Sprintf("%v, rev: %v\n%s", configBisectTag, prog.GitRevision, cf.Serialize()))
}

type minimizeLinuxCtx struct {
	kconf     *kconfig.KConfig
	config    *kconfig.ConfigFile
	pred      func(*kconfig.ConfigFile) (bool, error)
	transform func(*kconfig.ConfigFile)
	debugtracer.DebugTracer
}

func (ctx *minimizeLinuxCtx) minimizeAgainst(base *kconfig.ConfigFile) error {
	base = base.Clone()
	ctx.transform(base)
	// Don't do too many minimization runs, it will make bug bisections too long.
	// The purpose is only to reduce the number of build/boot/test errors due to bugs
	// in unrelated parts of the kernel.
	// Bisection is not getting much faster with smaller configs, only more reliable,
	// so there's a trade-off. Try to do best in 5 iterations, that's about 1.5 hours.
	const minimizeRuns = 5
	minConfig, err := ctx.kconf.Minimize(base, ctx.config, ctx.runPred, minimizeRuns, ctx)
	if err != nil {
		return err
	}
	ctx.config = minConfig
	return nil
}

func (ctx *minimizeLinuxCtx) dropInstrumentation(types []crash.Type) error {
	ctx.Log("check whether we can drop unnecessary instrumentation")
	oldTransform := ctx.transform
	transform := func(c *kconfig.ConfigFile) {
		oldTransform(c)
		setLinuxSanitizerConfigs(c, types, ctx)
	}
	newConfig := ctx.config.Clone()
	transform(newConfig)
	if bytes.Equal(ctx.config.Serialize(), newConfig.Serialize()) {
		ctx.Log("there was nothing we could disable; skip")
		return nil
	}
	ctx.SaveFile("no-instrumentation.config", newConfig.Serialize())
	ok, err := ctx.runPred(newConfig)
	if err != nil {
		return err
	}
	if ok {
		ctx.Log("the bug reproduces without the instrumentation")
		ctx.transform = transform
		ctx.config = newConfig
	}
	return nil
}

func (ctx *minimizeLinuxCtx) runPred(cfg *kconfig.ConfigFile) (bool, error) {
	cfg = cfg.Clone()
	ctx.transform(cfg)
	return ctx.pred(cfg)
}

func (ctx *minimizeLinuxCtx) getConfig() []byte {
	ctx.transform(ctx.config)
	return serialize(ctx.config)
}
