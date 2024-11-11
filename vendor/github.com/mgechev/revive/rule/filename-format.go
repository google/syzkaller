package rule

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"
	"unicode"

	"github.com/mgechev/revive/lint"
)

// FilenameFormatRule lints source filenames according to a set of regular expressions given as arguments
type FilenameFormatRule struct {
	format *regexp.Regexp
	sync.Mutex
}

// Apply applies the rule to the given file.
func (r *FilenameFormatRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	r.configure(arguments)

	filename := filepath.Base(file.Name)
	if r.format.MatchString(filename) {
		return nil
	}

	failureMsg := fmt.Sprintf("Filename %s is not of the format %s.%s", filename, r.format.String(), r.getMsgForNonASCIIChars(filename))
	return []lint.Failure{{
		Confidence: 1,
		Failure:    failureMsg,
		RuleName:   r.Name(),
		Node:       file.AST.Name,
	}}
}

func (r *FilenameFormatRule) getMsgForNonASCIIChars(str string) string {
	result := ""
	for _, c := range str {
		if c <= unicode.MaxASCII {
			continue
		}

		result += fmt.Sprintf(" Non ASCII character %c (%U) found.", c, c)
	}

	return result
}

// Name returns the rule name.
func (*FilenameFormatRule) Name() string {
	return "filename-format"
}

var defaultFormat = regexp.MustCompile("^[_A-Za-z0-9][_A-Za-z0-9-]*.go$")

func (r *FilenameFormatRule) configure(arguments lint.Arguments) {
	r.Lock()
	defer r.Unlock()

	if r.format != nil {
		return
	}

	argsCount := len(arguments)
	if argsCount == 0 {
		r.format = defaultFormat
		return
	}

	if argsCount > 1 {
		panic(fmt.Sprintf("rule %q expects only one argument, got %d %v", r.Name(), argsCount, arguments))
	}

	arg := arguments[0]
	str, ok := arg.(string)
	if !ok {
		panic(fmt.Sprintf("rule %q expects a string argument, got %v of type %T", r.Name(), arg, arg))
	}

	format, err := regexp.Compile(str)
	if err != nil {
		panic(fmt.Sprintf("rule %q expects a valid regexp argument, got %v for %s", r.Name(), err, arg))
	}

	r.format = format
}
