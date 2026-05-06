// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gerrit

import (
	"fmt"
)

func projectForRepo(repo string) (string, error) {
	project := projects[repo]
	if project == "" {
		return "", fmt.Errorf("gerrit: repo %q is not supported", repo)
	}
	return project, nil
}

var projects = func() map[string]string {
	// There are few others non-kernel.org-based, but we don't support them here now.
	kernelOrgRepos := []string{
		"bluetooth/bluetooth-next",
		"bpf/bpf",
		"bpf/bpf-next",
		"brauner/linux",
		"davem/net",
		"davem/net-next",
		"dhowells/keyutils",
		"dhowells/linux-fs",
		"dtor/input",
		"gregkh/char-misc",
		"gregkh/driver-core",
		"gregkh/staging",
		"gregkh/tty",
		"gregkh/usb",
		"herbert/crypto-2.6",
		"hid/hid",
		"jmorris/linux-security",
		"klassert/ipsec",
		"klassert/ipsec-next",
		"mellanox/linux",
		"paulmck/linux-rcu",
		"tip/tip",
		"tiwai/sound",
		"tj/cgroup",
		"tj/wq",
		"torvalds/linux",
		"viro/vfs",
		"will/linux",
		"zohar/linux-integrity",
	}
	res := map[string]string{}
	for _, repo := range kernelOrgRepos {
		project := "linux/kernel/git/" + repo
		const kernelOrgPrefix = "git.kernel.org/pub/scm/linux/kernel/git"
		const googleSrcPrefix = "kernel.googlesource.com/pub/scm/linux/kernel/git"
		res[fmt.Sprintf("git://%v/%v.git", kernelOrgPrefix, repo)] = project
		res[fmt.Sprintf("https://%v/%v.git", kernelOrgPrefix, repo)] = project
		res[fmt.Sprintf("https://%v/%v.git", googleSrcPrefix, repo)] = project
	}
	return res
}()
