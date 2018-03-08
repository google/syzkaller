// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !aetest

package dash

import "time"

// Stub config variable that merely makes link success.
// The app will panic in init with this empty config.
// When deploying the app one needs to replace this config with a real one.
// See an example below.
var config GlobalConfig

// Example config:
var _ = GlobalConfig{
	Namespaces: map[string]*Config{
		"upstream": &Config{
			Key: "123",
			Clients: map[string]string{
				"foo": "bar",
			},
			MailWithoutReport: false,
			WaitForRepro:      12 * time.Hour,
			Reporting: []Reporting{
				Reporting{
					Name:       "upstream",
					DailyLimit: 10,
					Filter:     reportAllFilter,
					Config: &EmailConfig{
						Email:           "syzkaller@googlegroups.com",
						MailMaintainers: true,
					},
				},
				Reporting{
					Name:   "another",
					Filter: reportSkipFilter,
				},
				Reporting{
					Name:   "yetanother",
					Filter: reportHoldFilter,
				},
			},
		},
	},
}
