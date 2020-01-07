// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"io"
	"net/mail"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/osutil"
)

type linux struct {
	*git
}

var _ Bisecter = new(linux)

func newLinux(dir string) *linux {
	ignoreCC := map[string]bool{
		"stable@vger.kernel.org": true,
	}
	return &linux{
		git: newGit(dir, ignoreCC),
	}
}

func (ctx *linux) PreviousReleaseTags(commit string) ([]string, error) {
	tags, err := ctx.git.previousReleaseTags(commit, false)
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

func gitParseReleaseTags(output []byte) ([]string, error) {
	var tags []string
	for _, tag := range bytes.Split(output, []byte{'\n'}) {
		if releaseTagRe.Match(tag) && gitReleaseTagToInt(string(tag)) != 0 {
			tags = append(tags, string(tag))
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		return gitReleaseTagToInt(tags[i]) > gitReleaseTagToInt(tags[j])
	})
	return tags, nil
}

func gitReleaseTagToInt(tag string) uint64 {
	matches := releaseTagRe.FindStringSubmatchIndex(tag)
	v1, err := strconv.ParseUint(tag[matches[2]:matches[3]], 10, 64)
	if err != nil {
		return 0
	}
	v2, err := strconv.ParseUint(tag[matches[4]:matches[5]], 10, 64)
	if err != nil {
		return 0
	}
	var v3 uint64
	if matches[6] != -1 {
		v3, err = strconv.ParseUint(tag[matches[6]:matches[7]], 10, 64)
		if err != nil {
			return 0
		}
	}
	return v1*1e6 + v2*1e3 + v3
}

func (ctx *linux) EnvForCommit(binDir, commit string, kernelConfig []byte) (*BisectEnv, error) {
	tagList, err := ctx.previousReleaseTags(commit, true)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool)
	for _, tag := range tagList {
		tags[tag] = true
	}
	env := &BisectEnv{
		Compiler:     filepath.Join(binDir, "gcc-"+linuxCompilerVersion(tags), "bin", "gcc"),
		KernelConfig: linuxDisableConfigs(kernelConfig, tags),
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
	case tags["v4.12"]:
		return "8.1.0"
	case tags["v4.11"]:
		return "7.3.0"
	default:
		return "5.5.0"
	}
}

func linuxDisableConfigs(config []byte, tags map[string]bool) []byte {
	prereq := map[string]string{
		// 5.2 has CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING which allows to test tomoyo better.
		// This config also enables CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER
		// but we need it disabled to boot older kernels.
		"CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER": "v5.2",
		// Kernel is boot broken before 4.15 due to double-free in vudc_probe:
		// https://lkml.org/lkml/2018/9/7/648
		// Fixed by e28fd56ad5273be67d0fae5bedc7e1680e729952.
		"CONFIG_USBIP_VUDC": "v4.15",
		// CONFIG_CAN causes:
		// all runs: crashed: INFO: trying to register non-static key in can_notifier
		// for v4.11..v4.12 and v4.12..v4.13 ranges.
		// Fixed by 74b7b490886852582d986a33443c2ffa50970169.
		"CONFIG_CAN": "v4.13",
		// Setup of network devices is broken before v4.12 with a "WARNING in hsr_get_node".
		// Fixed by 675c8da049fd6556eb2d6cdd745fe812752f07a8.
		"CONFIG_HSR": "v4.12",
		// Setup of network devices is broken before v4.12 with a "WARNING: ODEBUG bug in __sk_destruct"
		// coming from smc_release.
		"CONFIG_SMC": "v4.12",
		// Kernel is boot broken before 4.10 with a lockdep warning in vhci_hcd_probe.
		"CONFIG_USBIP_VHCI_HCD": "v4.10",
		"CONFIG_BT_HCIVHCI":     "v4.10",
		// Setup of network devices is broken before v4.7 with a deadlock involving team.
		"CONFIG_NET_TEAM": "v4.7",
		// Setup of network devices is broken before v4.5 with a warning in batadv_tvlv_container_remove.
		"CONFIG_BATMAN_ADV": "v4.5",
		// First, we disable coverage in pkg/bisect because it fails machine testing starting from 4.7.
		// Second, at 6689da155bdcd17abfe4d3a8b1e245d9ed4b5f2c CONFIG_KCOV selects CONFIG_GCC_PLUGIN_SANCOV
		// (why?), which is build broken for hundreds of revisions.
		"CONFIG_KCOV": "disable-always",
		// This helps to produce stable binaries in presence of kernel tag changes.
		"CONFIG_LOCALVERSION_AUTO": "disable-always",
		// BTF fails lots of builds with:
		// pahole version v1.9 is too old, need at least v1.13
		// Failed to generate BTF for vmlinux. Try to disable CONFIG_DEBUG_INFO_BTF.
		"CONFIG_DEBUG_INFO_BTF": "disable-always",
	}
	for cfg, tag := range prereq {
		if !tags[tag] {
			config = bytes.Replace(config, []byte(cfg+"=y"), []byte("# "+cfg+" is not set"), -1)
		}
	}
	return config
}

func (ctx *linux) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) ([]*Commit, error) {
	commits, err := ctx.git.Bisect(bad, good, trace, pred)
	if len(commits) == 1 {
		ctx.addMaintainers(commits[0])
	}
	return commits, err
}

func (ctx *linux) addMaintainers(com *Commit) {
	if len(com.CC) > 2 {
		return
	}
	list := ctx.getMaintainers(com.Hash, false)
	if len(list) < 3 {
		list = ctx.getMaintainers(com.Hash, true)
	}
	com.CC = email.MergeEmailLists(com.CC, list)
}

func (ctx *linux) getMaintainers(hash string, blame bool) []string {
	// See #1441 re --git-min-percent.
	args := "git show " + hash + " | " +
		filepath.FromSlash("scripts/get_maintainer.pl") +
		" --no-n --no-rolestats --git-min-percent=20"
	if blame {
		args += " --git-blame"
	}
	output, err := osutil.RunCmd(time.Minute, ctx.git.dir, "bash", "-c", args)
	if err != nil {
		return nil
	}
	var list []string
	for _, line := range strings.Split(string(output), "\n") {
		addr, err := mail.ParseAddress(line)
		if err != nil {
			continue
		}
		list = append(list, strings.ToLower(addr.Address))
	}
	return list
}
