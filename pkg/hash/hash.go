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

func Hash(pieces ...[]byte) Sig {
	h := sha1.New()
	for _, data := range pieces {
		h.Write(data)
	}
	var sig Sig
	copy(sig[:], h.Sum(nil))
	return sig
}

func String(pieces ...[]byte) string {
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

func FromString(str string) (Sig, error) {
	bin, err := hex.DecodeString(str)
	if err != nil {
		return Sig{}, fmt.Errorf("failed to decode sig '%v': %v", str, err)
	}
	if len(bin) != len(Sig{}) {
		return Sig{}, fmt.Errorf("failed to decode sig '%v': bad len", str)
	}
	var sig Sig
	for i, v := range bin {
		sig[i] = v
	}
	return sig, err
}
