// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !linux

package qemu

import (
	"fmt"
)

type snapshot struct{}

var errNotImplemented = fmt.Errorf("snapshots are not implemeneted")

func (inst *instance) snapshotClose() {
}

func (inst *instance) snapshotEnable() ([]string, error) {
	return nil, errNotImplemented
}

func (inst *instance) snapshotHandshake() error {
	return errNotImplemented
}

func (inst *instance) SetupSnapshot(input []byte) error {
	return errNotImplemented
}

func (inst *instance) RunSnapshot(input []byte) (result, output []byte, err error) {
	return nil, nil, errNotImplemented
}
