// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"google.golang.org/appengine"
)

func main() {
	installConfig(mainConfig)
	appengine.Main()
}
