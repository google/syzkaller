// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

type ProviderFactory func(ctx context.Context, model string) (backend.Provider, error)

var providers = make(map[string]ProviderFactory)

func RegisterProvider(name string, factory ProviderFactory) {
	if _, ok := providers[name]; ok {
		panic(fmt.Sprintf("provider %q is already registered", name))
	}
	providers[name] = factory
}
