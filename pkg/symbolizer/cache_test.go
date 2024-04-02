// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	called := make(map[cacheKey]bool)
	inner := func(bin string, pc uint64) ([]Frame, error) {
		key := cacheKey{bin, pc}
		assert.False(t, called[key])
		called[key] = true
		if bin == "error" {
			return nil, fmt.Errorf("error %v", pc)
		}
		return []Frame{{PC: pc, Func: bin + "_func"}}, nil
	}
	var cache Cache
	check := func(bin string, pc uint64, frames []Frame, err error) {
		gotFrames, gotErr := cache.Symbolize(inner, bin, pc)
		assert.Equal(t, gotFrames, frames)
		assert.Equal(t, gotErr, err)
	}
	check("foo", 1, []Frame{{PC: 1, Func: "foo_func"}}, nil)
	check("foo", 1, []Frame{{PC: 1, Func: "foo_func"}}, nil)
	check("foo", 2, []Frame{{PC: 2, Func: "foo_func"}}, nil)
	check("foo", 1, []Frame{{PC: 1, Func: "foo_func"}}, nil)
	check("error", 10, nil, errors.New("error 10"))
	check("error", 10, nil, errors.New("error 10"))
	check("error", 11, nil, errors.New("error 11"))
}
