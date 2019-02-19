// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build aetest

package dash

// isAppEngineTest is meant to be used in prod config to either
// load the config or just check its correctness.
const isAppEngineTest = true
