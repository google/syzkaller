
package email

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

func ParsePatch(message []byte) (diff string) {
	s := bufio.NewScanner(bytes.NewReader(message))
	diffStarted := false
	for s.Scan() {
		ln := s.Text()
		if lineMatchesDiffStart(ln) {
			diffStarted = true
			diff += ln + "\n"
			continue
		}
		if diffStarted {
			if ln == "" || ln == "--" || ln == "-- " || ln[0] == '>' {
				diffStarted = false
				continue
			}
			if strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "+") ||
				strings.HasPrefix(ln, "-") || strings.HasPrefix(ln, "@") ||
				strings.HasPrefix(ln, "================") {
				diff += ln + "\n"
				continue
			}
		}
	}
	err := s.Err()
	if err == bufio.ErrTooLong {
		// It's a problem of the incoming patch, rather than anything else.
		// Anyway, if a patch contains too long lines, we're probably not
		// interested in it, so let's pretent we didn't see it.
		diff = ""
		return
	} else if err != nil {
		panic("error while scanning from memory: " + err.Error())
	}
	return
}

var diffRegexps = []*regexp.Regexp{
	regexp.MustCompile(`^(---|\+\+\+) [^\s]`),
	regexp.MustCompile(`^diff --git`),
	regexp.MustCompile(`^index [0-9a-f]+\.\.[0-9a-f]+`),
	regexp.MustCompile(`^new file mode [0-9]+`),
	regexp.MustCompile(`^Index: [^\s]`),
}

func lineMatchesDiffStart(ln string) bool {
	for _, re := range diffRegexps {
		if re.MatchString(ln) {
			return true
		}
	}
	return false
}
