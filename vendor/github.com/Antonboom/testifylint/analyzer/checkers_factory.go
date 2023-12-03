package analyzer

import (
	"fmt"

	"github.com/Antonboom/testifylint/internal/checkers"
	"github.com/Antonboom/testifylint/internal/config"
)

// newCheckers accepts linter config and returns slices of enabled checkers sorted by priority.
func newCheckers(cfg config.Config) ([]checkers.RegularChecker, []checkers.AdvancedChecker, error) {
	enabledCheckers := cfg.EnabledCheckers
	if len(enabledCheckers) == 0 {
		enabledCheckers = checkers.EnabledByDefault()
	}
	if cfg.EnableAll {
		enabledCheckers = checkers.All()
	}

	checkers.SortByPriority(enabledCheckers)

	regularCheckers := make([]checkers.RegularChecker, 0, len(enabledCheckers))
	advancedCheckers := make([]checkers.AdvancedChecker, 0, len(enabledCheckers)/2)

	for _, name := range enabledCheckers {
		ch, ok := checkers.Get(name)
		if !ok {
			return nil, nil, fmt.Errorf("unknown checker %q", name)
		}

		switch c := ch.(type) {
		case *checkers.ExpectedActual:
			c.SetExpVarPattern(cfg.ExpectedActual.ExpVarPattern.Regexp)

		case *checkers.SuiteExtraAssertCall:
			c.SetMode(cfg.SuiteExtraAssertCall.Mode)
		}

		switch casted := ch.(type) {
		case checkers.RegularChecker:
			regularCheckers = append(regularCheckers, casted)
		case checkers.AdvancedChecker:
			advancedCheckers = append(advancedCheckers, casted)
		}
	}

	return regularCheckers, advancedCheckers, nil
}
