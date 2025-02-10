// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package hash

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type Sig [sha1.Size]byte

func Hash(pieces ...any) Sig {
	h := sha1.New()
	for _, data := range pieces {
		binary.Write(h, binary.LittleEndian, data)
	}
	var sig Sig
	copy(sig[:], h.Sum(nil))
	return sig
}

func String(pieces ...any) string {
	sig := Hash(pieces...)
	return sig.String()
}

func (sig *Sig) String() string {
	return hex.EncodeToString((*sig)[:])
}

// Truncate64 returns first 64 bits of the hash as int64.
func (sig *Sig) Truncate64() int64 {
	var v int64
	if err := binary.Read(bytes.NewReader((*sig)[:]), binary.LittleEndian, &v); err != nil {
		panic(fmt.Sprintf("failed convert hash to id: %v", err))
	}
	return v
}
