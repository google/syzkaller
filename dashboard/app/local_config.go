// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

func init() {
	checkConfig(localConfig)
	mainConfig = localConfig
}

var localConfig = &GlobalConfig{
	AccessLevel: AccessPublic,
	ACL: []*ACLItem{
		{
			Email:  "test@example.com",
			Access: AccessAdmin,
		},
	},
	Clients: map[string]string{
		"global-local": "Uvx0zUMD4QreHaASliwXVBaGlOnlcZlR",
	},
	ContactEmail:     "dvyukov@google.com",
	DefaultNamespace: "upstream",
	Namespaces: map[string]*Config{
		"upstream": {
			AccessLevel:      AccessPublic,
			AI:               true,
			DisplayTitle:     "Linux",
			SimilarityDomain: "Linux",
			Key:              "Uvx0zUMD4QreHaASliwXVBaGlOnlcZlR",
			Clients: map[string]string{
				"upstream-client": "Uvx0zUMD4QreHaASliwXVBaGlOnlcZlR",
			},
			Repos: []KernelRepo{
				{
					URL:               "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
					Branch:            "master",
					Alias:             "upstream",
					ReportingPriority: 9,
				},
			},
			MailWithoutReport: true,
			WaitForRepro:      0,
			Managers:          map[string]ConfigManager{},
			Reporting: []Reporting{
				{
					AccessLevel:  AccessPublic,
					Name:         "upstream",
					DisplayTitle: "upstream",
					DailyLimit:   10,
					Config: &EmailConfig{
						Email:         "dvyukov@google.com",
						SubjectPrefix: "[local syzbot]",
					},
				},
			},
		},
	},
}
