// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"strings"
	"time"

	// Import all targets, so that users only need to import sys.
	_ "github.com/google/syzkaller/sys/akaros/gen"
	_ "github.com/google/syzkaller/sys/freebsd/gen"
	_ "github.com/google/syzkaller/sys/fuchsia/gen"
	_ "github.com/google/syzkaller/sys/linux/gen"
	_ "github.com/google/syzkaller/sys/netbsd/gen"
	_ "github.com/google/syzkaller/sys/openbsd/gen"
	_ "github.com/google/syzkaller/sys/test/gen"
	_ "github.com/google/syzkaller/sys/windows/gen"
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
		if GitRevisionDate, err = time.Parse("Mon Jan 2 15:04:05 2006 -0700", gitRevisionDate); err != nil {
			panic(err)
		}
	}
}
