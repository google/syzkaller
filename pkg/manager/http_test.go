// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"io"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

func TestHttpTemplates(t *testing.T) {
	for _, typ := range templTypes {
		t.Run(typ.title, func(t *testing.T) {
			data := testutil.RandValue(t, typ.data)
			if err := typ.templ.Execute(io.Discard, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}
