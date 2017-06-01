// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package hash

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

type Sig [sha1.Size]byte

func Hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

func String(data []byte) string {
	sig := Hash(data)
	return sig.String()
}

func (sig *Sig) String() string {
	return hex.EncodeToString((*sig)[:])
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
