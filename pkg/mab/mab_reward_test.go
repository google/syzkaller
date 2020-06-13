// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mab_test

import (
	"testing"

	. "github.com/google/syzkaller/pkg/mab"
)

func TestRewardUpdate(t *testing.T) {
	reward := Reward{
		Count:      0,
		TotalCov:   0.0,
		TotalTime:  0.0,
		TotalCov2:  0.0,
		TotalTime2: 0.0,
	}
	reward_expected := Reward{
		Count:      1,
		TotalCov:   2.0,
		TotalTime:  4.0,
		TotalCov2:  4.0,
		TotalTime2: 16.0,
	}
	reward.Update(2.0, 4.0)
	if reward != reward_expected {
		t.Fatal("Reward is not updated correctly")
	}
}
