// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

// The objective of this file is to collect config parts and routines useful for Linux bugs management,
// thus reducing the size of the dashboard config file.

// canBeVfsBug determines whether a bug could belong to the VFS subsystem itself.
func canBeVfsBug(bug *Bug) bool {
	for _, subsystem := range bug.Tags.Subsystems {
		if subsystem.Name == "vfs" {
			return true
		}
	}
	return false
}
