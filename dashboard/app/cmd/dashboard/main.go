// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/dashboard/app"
	"github.com/google/syzkaller/dashboard/app/config"
)

func main() {
	app.Main(config.Config)
}
