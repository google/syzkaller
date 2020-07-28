// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type linux struct {
	*git
}

var _ Bisecter = new(linux)
var _ ConfigMinimizer = new(linux)

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
		KernelConfig: linuxAlterConfigs(kernelConfig, tags),
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

func linuxAlterConfigs(config []byte, tags map[string]bool) []byte {
	disable := map[string]string{
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
		// This config only adds debug output. It should not be enabled at all,
		// but it was accidentially enabled on some instances for some periods of time,
		// and kernel is boot-broken for prolonged ranges of commits with deadlock
		// which makes bisections take weeks.
		"CONFIG_DEBUG_KOBJECT": "disable-always",
	}
	for cfg, tag := range disable {
		if !tags[tag] {
			config = bytes.Replace(config, []byte(cfg+"=y"), []byte("# "+cfg+" is not set"), -1)
		}
	}
	alter := []struct {
		From string
		To   string
		Tag  string
	}{
		// Even though ORC unwinder was introduced a long time ago, it might have been broken for
		// some time. 5.4 is chosen as a version tag, where ORC unwinder seems to work properly.
		{"CONFIG_UNWINDER_ORC", "CONFIG_UNWINDER_FRAME_POINTER", "v5.4"},
	}
	for _, a := range alter {
		if !tags[a.Tag] {
			config = bytes.Replace(config, []byte(a.From+"=y"), []byte("# "+a.From+" is not set"), -1)
			config = bytes.Replace(config, []byte("# "+a.To+" is not set"), []byte(a.To+"=y"), -1)
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

func (ctx *linux) Minimize(original, baseline []byte, trace io.Writer,
	pred func(test []byte) (BisectResult, error)) ([]byte, error) {
	if bytes.HasPrefix(original, []byte(configBisectTag)) {
		fmt.Fprintf(trace, "# configuration already minimized\n")
		return original, nil
	}
	bisectDir, err := ioutil.TempDir("", "syz-config-bisect")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for config bisect: %v", err)
	}
	defer os.RemoveAll(bisectDir)
	kernelConfig := filepath.Join(bisectDir, "kernel.config")
	kernelBaselineConfig := filepath.Join(bisectDir, "kernel.baseline_config")
	if err := ctx.prepareConfigBisectEnv(kernelConfig, kernelBaselineConfig, original, baseline); err != nil {
		return nil, err
	}

	fmt.Fprintf(trace, "# start config bisection\n")
	configBisect := filepath.Join(ctx.git.dir, "tools", "testing", "ktest", "config-bisect.pl")
	output, err := osutil.RunCmd(time.Hour, "", configBisect,
		"-l", ctx.git.dir, "-r", "-b", ctx.git.dir, kernelBaselineConfig, kernelConfig)
	if err != nil {
		return nil, fmt.Errorf("config bisect failed: %v", err)
	}
	fmt.Fprintf(trace, "# config-bisect.pl -r:\n%s", output)
	for {
		config, err := ioutil.ReadFile(filepath.Join(ctx.git.dir, ".config"))
		if err != nil {
			return nil, fmt.Errorf("failed to read .config: %v", err)
		}

		testRes, err := pred(config)
		if err != nil {
			return nil, err
		}
		if testRes == BisectSkip {
			return nil, fmt.Errorf("unable to test, stopping config bisection")
		}
		verdict := "good"
		if testRes == BisectBad {
			verdict = "bad"
		}

		output1, err := osutil.RunCmd(time.Hour, "", configBisect,
			"-l", ctx.git.dir, "-b", ctx.git.dir, kernelBaselineConfig, kernelConfig, verdict)
		fmt.Fprintf(trace, "# config-bisect.pl %v:\n%s", verdict, output1)
		output = append(output, output1...)
		if err != nil {
			if verr, ok := err.(*osutil.VerboseError); ok && verr.ExitCode == 2 {
				break
			}
			return nil, fmt.Errorf("config bisect failed: %v", err)
		}
	}
	fmt.Fprintf(trace, "# config_bisect.pl finished\n")
	configOptions := ctx.parseConfigBisectLog(trace, output)
	if len(configOptions) == 0 {
		return nil, fmt.Errorf("no config changes in the config bisect log:\n%s", output)
	}

	// Parse minimalistic configuration to generate the crash.
	minimizedConfig, err := ctx.generateMinConfig(configOptions, bisectDir, kernelBaselineConfig)
	if err != nil {
		return nil, fmt.Errorf("generating minimized config failed: %v", err)
	}
	return minimizedConfig, nil
}

func (ctx *linux) prepareConfigBisectEnv(kernelConfig, kernelBaselineConfig string, original, baseline []byte) error {
	current, err := ctx.HeadCommit()
	if err != nil {
		return err
	}

	// Call EnvForCommit if some options needs to be adjusted.
	bisectEnv, err := ctx.EnvForCommit("", current.Hash, original)
	if err != nil {
		return fmt.Errorf("failed create commit environment: %v", err)
	}
	if err := osutil.WriteFile(kernelConfig, bisectEnv.KernelConfig); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	// Call EnvForCommit again if some options needs to be adjusted in baseline.
	bisectEnv, err = ctx.EnvForCommit("", current.Hash, baseline)
	if err != nil {
		return fmt.Errorf("failed create commit environment: %v", err)
	}
	if err := osutil.WriteFile(kernelBaselineConfig, bisectEnv.KernelConfig); err != nil {
		return fmt.Errorf("failed to write minimum config file: %v", err)
	}
	return nil
}

//       Takes in config_bisect.pl output:
//       Hmm, can't make any more changes without making good == bad?
//       Difference between good (+) and bad (-)
//        +DRIVER1=n
//        +DRIVER2=n
//        -DRIVER3=n
//        -DRIVER4=n
//        DRIVER5 n -> y
//        DRIVER6 y -> n
//       See good and bad configs for details:
//       good: /mnt/work/linux/good_config.tmp
//       bad:  /mnt/work/linux/bad_config.tmp
func (ctx *linux) parseConfigBisectLog(trace io.Writer, bisectLog []byte) []string {
	var configOptions []string
	start := false
	for s := bufio.NewScanner(bytes.NewReader(bisectLog)); s.Scan(); {
		line := s.Text()
		if strings.Contains(line, "See good and bad configs for details:") {
			break
		}
		if !start {
			if strings.Contains(line, "Difference between good (+) and bad (-)") {
				start = true
			}
			continue
		}
		if strings.HasPrefix(line, "+") {
			// This is option only in good config. Drop it as it's dependent
			// on some option which is disabled in bad config.
			continue
		}
		option, selection := "", ""
		if strings.HasPrefix(line, "-") {
			// -CONFIG_DRIVER_1=n
			// Remove preceding -1 and split to option and selection
			fields := strings.Split(strings.TrimPrefix(line, "-"), "=")
			option = fields[0]
			selection = fields[len(fields)-1]
		} else {
			// DRIVER_OPTION1 n -> y
			fields := strings.Split(strings.TrimPrefix(line, " "), " ")
			option = fields[0]
			selection = fields[len(fields)-1]
		}

		configOptioon := "CONFIG_" + option + "=" + selection
		if selection == "n" {
			configOptioon = "# CONFIG_" + option + " is not set"
		}
		configOptions = append(configOptions, configOptioon)
	}

	fmt.Fprintf(trace, "# found config option changes %v\n", configOptions)
	return configOptions
}

func (ctx *linux) generateMinConfig(configOptions []string, outdir, baseline string) ([]byte, error) {
	kernelAdditionsConfig := filepath.Join(outdir, "kernel.additions_config")
	if err := osutil.WriteFile(kernelAdditionsConfig, []byte(strings.Join(configOptions, "\n"))); err != nil {
		return nil, fmt.Errorf("failed to write config additions file: %v", err)
	}

	_, err := osutil.RunCmd(time.Hour, "", filepath.Join(ctx.git.dir, "scripts", "kconfig", "merge_config.sh"),
		"-m", "-O", outdir, baseline, kernelAdditionsConfig)
	if err != nil {
		return nil, fmt.Errorf("config merge failed: %v", err)
	}

	minConfig, err := ioutil.ReadFile(filepath.Join(outdir, ".config"))
	if err != nil {
		return nil, fmt.Errorf("failed to read merged configuration: %v", err)
	}
	minConfig = append([]byte(fmt.Sprintf("%v, rev: %v\n", configBisectTag, prog.GitRevision)), minConfig...)
	return minConfig, nil
}
