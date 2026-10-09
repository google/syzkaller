// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package firecracker

import (
	"fmt"
	"time"
)

// Snapshot mode is not implemented for firecracker. Unlike crosvm, firecracker has no
// file-backed guest-physical MMIO mapping we could use as the host/guest shared memory
// region (the executor's snapshot transport, see executor/snapshot.h), and its snapshot
// API (/snapshot/create + /snapshot/load) serializes all of guest RAM, which would not
// let us hand a fresh input to the guest before each restore. Firecracker is therefore
// used only in the normal (non-snapshot) fuzzing mode over the tap network.
type snapshot struct{}

var errNotImplemented = fmt.Errorf("snapshots are not implemented for firecracker")

func (inst *instance) snapshotClose() {
}

func (inst *instance) SetupSnapshot(input []byte) error {
	return errNotImplemented
}

func (inst *instance) RunSnapshot(timeout time.Duration, input []byte) (result, output []byte, err error) {
	return nil, nil, errNotImplemented
}
