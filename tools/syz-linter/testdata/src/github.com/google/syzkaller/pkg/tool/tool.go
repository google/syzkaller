// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tool

func Failf(msg string, args ...interface{}) {}
func Fail(err error) {}
