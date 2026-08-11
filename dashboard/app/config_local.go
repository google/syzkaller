// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

func init() {
	if mainConfig == nil {
		mainConfig = localConfig
	}
}

var localConfig = &GlobalConfig{
	AccessLevel:      AccessPublic,
	DefaultNamespace: "upstream",
	DungeonNamespace: "upstream",
	Clients: map[string]APIClient{
		"local_ui_global_client": {Key: "localuipasswordlocaluipasswordlocaluipassword"},
	},
	Namespaces: map[string]*Config{
		"upstream": {
			DisplayTitle: "Linux",
			AccessLevel:  AccessPublic,
			Key:          "upstreamkey12345678901234567890",
			Clients: map[string]APIClient{
				"local_ui_client": {Key: "localuipasswordlocaluipasswordlocaluipassword"},
			},
			Repos: []KernelRepo{
				{
					URL:    "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
					Branch: "master",
					Alias:  "upstream",
				},
			},
			Reporting: []Reporting{
				{
					AccessLevel: AccessPublic,
					Name:        "email-reporting",
					DailyLimit:  1000,
					Config: &EmailConfig{
						Email:            "test@syzkaller.com",
						HandleListEmails: true,
						SubjectPrefix:    "[syzbot]",
					},
				},
			},
		},
	},
}
