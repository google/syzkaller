// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"fmt"
	"net/mail"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type linux struct {
	*git
}

var (
	_ Bisecter        = new(linux)
	_ ConfigMinimizer = new(linux)
)

func newLinux(dir string, opts []RepoOpt) *linux {
	ignoreCC := map[string]bool{
		"stable@vger.kernel.org": true,
	}
	return &linux{
		git: newGit(dir, ignoreCC, opts),
	}
}

func (ctx *linux) PreviousReleaseTags(commit string) ([]string, error) {
	tags, err := ctx.git.previousReleaseTags(commit, false, false, false)
	if err != nil {
		return nil, err
	}
	for i, tag := range tags {
		if tag == "v4.5" {
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
			// of getting correct result (see #1532). So we now stop at 4.6.
			// 4.6 is somewhat arbitrary, we've seen lots of wrong results in 4.5..4.6 range,
			// but there is definitive reason for 4.6. Most likely later we want to bump it
			// even more (as new releases are produced). Next good candidate may be 4.11
			// because then we won't need gcc 5.5.
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
	matches := releaseTagRe.FindStringSubmatchIndex(tag)
	if matches == nil {
		return 0
	}
	v1, err := strconv.ParseUint(tag[matches[2]:matches[3]], 10, 64)
	if err != nil {
		return 0
	}
	v2, err := strconv.ParseUint(tag[matches[4]:matches[5]], 10, 64)
	if err != nil {
		return 0
	}
	rc := uint64(999)
	if matches[6] != -1 {
		if !includeRC {
			return 0
		}
		rc, err = strconv.ParseUint(tag[matches[6]:matches[7]], 10, 64)
		if err != nil {
			return 0
		}
	}
	var v3 uint64
	if matches[8] != -1 {
		v3, err = strconv.ParseUint(tag[matches[8]:matches[9]], 10, 64)
		if err != nil {
			return 0
		}
	}
	return v1*1e9 + v2*1e6 + rc*1e3 + v3
}

func (ctx *linux) EnvForCommit(binDir, commit string, kernelConfig []byte) (*BisectEnv, error) {
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
	linuxAlterConfigs(cf, tags)
	env := &BisectEnv{
		Compiler:     filepath.Join(binDir, "gcc-"+linuxCompilerVersion(tags), "bin", "gcc"),
		KernelConfig: cf.Serialize(),
	}
	// v4.0 doesn't boot with our config nor with defconfig, it halts on an interrupt in x86_64_start_kernel.
	if !tags["v4.1"] {
		_, err := ctx.git.git("cherry-pick", "--no-commit", "99124e4db5b7b70daeaaf1d88a6a8078a0004c6e")
		if err != nil {
			return nil, err
		}
	}

	return env, nil
}

func linuxCompilerVersion(tags map[string]bool) string {
	switch {
	case tags["v5.9"]:
		return "10.1.0"
	case tags["v4.12"]:
		return "8.1.0"
	case tags["v4.11"]:
		return "7.3.0"
	default:
		return "5.5.0"
	}
}

func linuxAlterConfigs(cf *kconfig.ConfigFile, tags map[string]bool) {
	const disableAlways = "disable-always"
	// If tags is nil, disable only configs marked as disableAlways.
	checkTag := func(tag string) bool {
		return tags != nil && !tags[tag] ||
			tags == nil && tag == disableAlways
	}
	disable := map[string]string{
		// 5.2 has CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING which allows to test tomoyo better.
		// This config also enables CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER
		// but we need it disabled to boot older kernels.
		"SECURITY_TOMOYO_OMIT_USERSPACE_LOADER": "v5.2",
		// Kernel is boot broken before 4.15 due to double-free in vudc_probe:
		// https://lkml.org/lkml/2018/9/7/648
		// Fixed by e28fd56ad5273be67d0fae5bedc7e1680e729952.
		"USBIP_VUDC": "v4.15",
		// CONFIG_CAN causes:
		// all runs: crashed: INFO: trying to register non-static key in can_notifier
		// for v4.11..v4.12 and v4.12..v4.13 ranges.
		// Fixed by 74b7b490886852582d986a33443c2ffa50970169.
		"CAN": "v4.13",
		// Setup of network devices is broken before v4.12 with a "WARNING in hsr_get_node".
		// Fixed by 675c8da049fd6556eb2d6cdd745fe812752f07a8.
		"HSR": "v4.12",
		// Setup of network devices is broken before v4.12 with a "WARNING: ODEBUG bug in __sk_destruct"
		// coming from smc_release.
		"SMC": "v4.12",
		// Kernel is boot broken before 4.10 with a lockdep warning in vhci_hcd_probe.
		"USBIP_VHCI_HCD": "v4.10",
		"BT_HCIVHCI":     "v4.10",
		// Setup of network devices is broken before v4.7 with a deadlock involving team.
		"NET_TEAM": "v4.7",
		// Setup of network devices is broken before v4.5 with a warning in batadv_tvlv_container_remove.
		"BATMAN_ADV": "v4.5",
		// UBSAN is broken in multiple ways before v5.3, see:
		// https://github.com/google/syzkaller/issues/1523#issuecomment-696514105
		"UBSAN": "v5.3",
		// First, we disable coverage in pkg/bisect because it fails machine testing starting from 4.7.
		// Second, at 6689da155bdcd17abfe4d3a8b1e245d9ed4b5f2c CONFIG_KCOV selects CONFIG_GCC_PLUGIN_SANCOV
		// (why?), which is build broken for hundreds of revisions.
		"KCOV": disableAlways,
		// This helps to produce stable binaries in presence of kernel tag changes.
		"LOCALVERSION_AUTO": disableAlways,
		// BTF fails lots of builds with:
		// pahole version v1.9 is too old, need at least v1.13
		// Failed to generate BTF for vmlinux. Try to disable CONFIG_DEBUG_INFO_BTF.
		"DEBUG_INFO_BTF": disableAlways,
		// This config only adds debug output. It should not be enabled at all,
		// but it was accidentially enabled on some instances for some periods of time,
		// and kernel is boot-broken for prolonged ranges of commits with deadlock
		// which makes bisections take weeks.
		"DEBUG_KOBJECT": disableAlways,
		// This config is causing problems to kernel signature calculation as new initramfs is generated
		// as a part of every build. Due to this init.data section containing this generated initramfs
		// is differing between builds causing signture being random number.
		"BLK_DEV_INITRD": disableAlways,
	}
	for cfg, tag := range disable {
		if checkTag(tag) {
			cf.Unset(cfg)
		}
	}
	alter := []struct {
		From string
		To   string
		Tag  string
	}{
		// Even though ORC unwinder was introduced a long time ago, it might have been broken for
		// some time. 5.4 is chosen as a version tag, where ORC unwinder seems to work properly.
		{"UNWINDER_ORC", "UNWINDER_FRAME_POINTER", "v5.4"},
	}
	for _, a := range alter {
		if checkTag(a.Tag) {
			cf.Unset(a.From)
			cf.Set(a.To, kconfig.Yes)
		}
	}
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
	output, err := osutil.RunCmd(time.Minute, ctx.git.dir, "bash", "-c", args)
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

const configBisectTag = "# Minimized by syzkaller"

func (ctx *linux) Minimize(target *targets.Target, original, baseline []byte,
	dt debugtracer.DebugTracer, pred func(test []byte) (BisectResult, error)) ([]byte, error) {
	if bytes.HasPrefix(original, []byte(configBisectTag)) {
		dt.Log("# configuration already minimized\n")
		return original, nil
	}
	kconf, err := kconfig.Parse(target, filepath.Join(ctx.git.dir, "Kconfig"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kconfig: %v", err)
	}
	originalConfig, err := kconfig.ParseConfigData(original, "original")
	if err != nil {
		return nil, err
	}
	baselineConfig, err := kconfig.ParseConfigData(baseline, "baseline")
	if err != nil {
		return nil, err
	}
	linuxAlterConfigs(originalConfig, nil)
	linuxAlterConfigs(baselineConfig, nil)
	kconfPred := func(candidate *kconfig.ConfigFile) (bool, error) {
		res, err := pred(serialize(candidate))
		return res == BisectBad, err
	}
	minConfig, err := kconf.Minimize(baselineConfig, originalConfig, kconfPred, dt)
	if err != nil {
		return nil, err
	}
	return serialize(minConfig), nil
}

func serialize(cf *kconfig.ConfigFile) []byte {
	return []byte(fmt.Sprintf("%v, rev: %v\n%s", configBisectTag, prog.GitRevision, cf.Serialize()))
}
