// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"strings"
	"time"
)

var (
	GitRevision     string    // emitted by Makefile, may contain + at the end
	GitRevisionBase string    // without +
	gitRevisionDate string    // emitted by Makefile
	GitRevisionDate time.Time // parsed from gitRevisionDate
)

func init() {
	GitRevisionBase = strings.Replace(GitRevision, "+", "", -1)
	if gitRevisionDate != "" {
		var err error
		if GitRevisionDate, err = time.Parse("20060102-150405", gitRevisionDate); err != nil {
			panic(err)
		}
	}
}
