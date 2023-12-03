package rule

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/mgechev/revive/lint"
)

// ImportAliasNamingRule lints import alias naming.
type ImportAliasNamingRule struct {
	configured       bool
	namingRuleRegexp *regexp.Regexp
	sync.Mutex
}

const defaultNamingRule = "^[a-z][a-z0-9]{0,}$"

var defaultNamingRuleRegexp = regexp.MustCompile(defaultNamingRule)

func (r *ImportAliasNamingRule) configure(arguments lint.Arguments) {
	r.Lock()
	defer r.Unlock()
	if r.configured {
		return
	}

	if len(arguments) < 1 {
		r.namingRuleRegexp = defaultNamingRuleRegexp
		return
	}

	namingRule, ok := arguments[0].(string) // Alt. non panicking version
	if !ok {
		panic(fmt.Sprintf("Invalid argument '%v' for 'import-alias-naming' rule. Expecting string, got %T", arguments[0], arguments[0]))
	}

	var err error
	r.namingRuleRegexp, err = regexp.Compile(namingRule)
	if err != nil {
		panic(fmt.Sprintf("Invalid argument to the import-alias-naming rule. Expecting %q to be a valid regular expression, got: %v", namingRule, err))
	}
}

// Apply applies the rule to given file.
func (r *ImportAliasNamingRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	r.configure(arguments)

	var failures []lint.Failure

	for _, is := range file.AST.Imports {
		path := is.Path
		if path == nil {
			continue
		}

		alias := is.Name
		if alias == nil || alias.Name == "_" {
			continue
		}

		if !r.namingRuleRegexp.MatchString(alias.Name) {
			failures = append(failures, lint.Failure{
				Confidence: 1,
				Failure:    fmt.Sprintf("import name (%s) must match the regular expression: %s", alias.Name, r.namingRuleRegexp.String()),
				Node:       alias,
				Category:   "imports",
			})
		}
	}

	return failures
}

// Name returns the rule name.
func (*ImportAliasNamingRule) Name() string {
	return "import-alias-naming"
}
