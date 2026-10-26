// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package config holds the syzbot dashboard configuration.
package config

import "github.com/google/syzkaller/dashboard/app"

// Get returns the dashboard config.
// This is a stub that allows the binary to compile in upstream checkouts.
// Deployments replace this package with the actual config.
// Running the binary without replacing it will panic in app.Main.
func Get() *app.GlobalConfig {
	return nil
}
