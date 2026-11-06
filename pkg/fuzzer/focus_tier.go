// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"github.com/google/syzkaller/pkg/fuzzer/queue"
)

// focusTier holds the triage and mutation job queues for a group of inputs.
// Currently, all inputs share the single catch-all tier.
type focusTier struct {
	weight      float64
	triageQueue *queue.DynamicOrderer
	smashQueue  *queue.PlainQueue
	hintsQueue  *queue.PlainQueue
}

func newFocusTier(weight float64) *focusTier {
	return &focusTier{
		weight:      weight,
		triageQueue: queue.DynamicOrder(),
		smashQueue:  queue.Plain(),
		hintsQueue:  queue.Plain(),
	}
}

func (fuzzer *Fuzzer) catchAllTier() *focusTier {
	return fuzzer.tiers[len(fuzzer.tiers)-1]
}
