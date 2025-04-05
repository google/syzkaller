// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build windows || 386 || arm

package image

import (
	"bytes"
	"sync"
)

var decompressMu sync.Mutex

func mustDecompress(compressed []byte) (data []byte, dtor func()) {
	// Don't decompress more than one image at a time since it can consume lots of memory.
	// Reconsider when/if we move mutation to the host process.
	decompressMu.Lock()
	buf := new(bytes.Buffer)
	if err := decompressWriter(buf, compressed); err != nil {
		panic(err)
	}
	return buf.Bytes(), decompressMu.Unlock
}
