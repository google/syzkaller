// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"errors"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/osutil"
)

// Checkpatch runs scripts/checkpatch.pl on the current diff in the repo.
// It returns the output string, a boolean indicating if checkpatch found issues, and an error.
func Checkpatch(repo string) (string, bool, error) {
	diff, err := patchdiff.Diff(repo, "HEAD")
	if err != nil {
		return "", false, err
	}

	cmd := osutil.Command("scripts/checkpatch.pl", "--no-tree", "-")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(diff)

	output, err := osutil.Run(1*time.Minute, cmd)
	if err != nil {
		if verr, ok := errors.AsType[*osutil.VerboseError](err); ok {
			return string(verr.Output), true, nil
		}
		return "", false, err
	}
	return string(output), false, nil
}
