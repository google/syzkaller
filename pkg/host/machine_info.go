// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

func CollectMachineInfo() ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, pair := range machineInfoFuncs {
		fmt.Fprintf(buf, "[%s]\n", pair.name)
		err := pair.fn(buf)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			fmt.Fprintf(buf, "%v\n", err)
		}
		fmt.Fprintf(buf, "%v\n\n", strings.Repeat("-", 80))
	}
	return buf.Bytes(), nil
}

var machineInfoFuncs []machineInfoFunc

type machineInfoFunc struct {
	name string
	fn   func(*bytes.Buffer) error
}
