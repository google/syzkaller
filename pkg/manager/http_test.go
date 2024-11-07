// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"io"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

func TestHttpTemplates(t *testing.T) {
	for i, typ := range templTypes {
		t.Run(fmt.Sprintf("%v_%T", i, typ.data), func(t *testing.T) {
			data := testutil.RandValue(t, typ.data)
			if err := typ.templ.Execute(io.Discard, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}
