
package prog

import (
	"strings"
	"time"
)

const defaultGitRevision = "unknown"

var (
	GitRevision     = defaultGitRevision // emitted by Makefile, may contain + at the end
	GitRevisionBase string               // without +
	gitRevisionDate string               // emitted by Makefile
	GitRevisionDate time.Time            // parsed from gitRevisionDate
)

func GitRevisionKnown() bool {
	return GitRevision != defaultGitRevision
}

func init() {
	GitRevisionBase = strings.ReplaceAll(GitRevision, "+", "")
	if gitRevisionDate != "" {
		var err error
		if GitRevisionDate, err = time.Parse("20060102-150405", gitRevisionDate); err != nil {
			panic(err)
		}
	}
}
