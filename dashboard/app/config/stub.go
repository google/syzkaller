// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package config holds the syzbot dashboard configuration.
package config

import "github.com/google/syzkaller/dashboard/app"

// Config is a stub that allows the binary to compile in upstream checkouts.
// Running the binary without replacing this package will panic in app.Main.
var Config *app.GlobalConfig
