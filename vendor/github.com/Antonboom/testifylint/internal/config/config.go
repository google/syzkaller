package config

import (
	"flag"

	"github.com/Antonboom/testifylint/internal/checkers"
)

// NewDefault builds default testifylint config.
func NewDefault() Config {
	return Config{
		EnableAll:       false,
		EnabledCheckers: checkers.EnabledByDefault(),
		ExpectedActual: ExpectedActualConfig{
			ExpVarPattern: RegexpValue{checkers.DefaultExpectedVarPattern},
		},
		SuiteExtraAssertCall: SuiteExtraAssertCallConfig{
			Mode: checkers.DefaultSuiteExtraAssertCallMode,
		},
	}
}

// Config implements testifylint configuration.
type Config struct {
	EnableAll            bool
	EnabledCheckers      KnownCheckersValue
	ExpectedActual       ExpectedActualConfig
	SuiteExtraAssertCall SuiteExtraAssertCallConfig
}

// ExpectedActualConfig implements configuration of checkers.ExpectedActual.
type ExpectedActualConfig struct {
	ExpVarPattern RegexpValue
}

// SuiteExtraAssertCallConfig implements configuration of checkers.SuiteExtraAssertCall.
type SuiteExtraAssertCallConfig struct {
	Mode checkers.SuiteExtraAssertCallMode
}

// BindToFlags binds Config fields to according flags.
func BindToFlags(cfg *Config, fs *flag.FlagSet) {
	fs.BoolVar(&cfg.EnableAll, "enable-all", false, "enable all checkers")
	fs.Var(&cfg.EnabledCheckers, "enable", "comma separated list of enabled checkers")
	fs.Var(&cfg.ExpectedActual.ExpVarPattern, "expected-actual.pattern", "regexp for expected variable name")
	fs.Var(NewEnumValue(suiteExtraAssertCallModeAsString, &cfg.SuiteExtraAssertCall.Mode),
		"suite-extra-assert-call.mode", "to require or remove extra Assert() call")
}

var suiteExtraAssertCallModeAsString = map[string]checkers.SuiteExtraAssertCallMode{
	"remove":  checkers.SuiteExtraAssertCallModeRemove,
	"require": checkers.SuiteExtraAssertCallModeRequire,
}
