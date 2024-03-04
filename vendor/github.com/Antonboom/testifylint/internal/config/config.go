package config

import (
	"errors"
	"flag"
	"fmt"

	"github.com/Antonboom/testifylint/internal/checkers"
)

// NewDefault builds default testifylint config.
func NewDefault() Config {
	return Config{
		EnableAll:        false,
		DisabledCheckers: nil,
		DisableAll:       false,
		EnabledCheckers:  nil,
		ExpectedActual: ExpectedActualConfig{
			ExpVarPattern: RegexpValue{checkers.DefaultExpectedVarPattern},
		},
		RequireError: RequireErrorConfig{
			FnPattern: RegexpValue{nil},
		},
		SuiteExtraAssertCall: SuiteExtraAssertCallConfig{
			Mode: checkers.DefaultSuiteExtraAssertCallMode,
		},
	}
}

// Config implements testifylint configuration.
type Config struct {
	EnableAll        bool
	DisabledCheckers KnownCheckersValue
	DisableAll       bool
	EnabledCheckers  KnownCheckersValue

	ExpectedActual       ExpectedActualConfig
	RequireError         RequireErrorConfig
	SuiteExtraAssertCall SuiteExtraAssertCallConfig
}

// ExpectedActualConfig implements configuration of checkers.ExpectedActual.
type ExpectedActualConfig struct {
	ExpVarPattern RegexpValue
}

// RequireErrorConfig implements configuration of checkers.RequireError.
type RequireErrorConfig struct {
	FnPattern RegexpValue
}

// SuiteExtraAssertCallConfig implements configuration of checkers.SuiteExtraAssertCall.
type SuiteExtraAssertCallConfig struct {
	Mode checkers.SuiteExtraAssertCallMode
}

func (cfg Config) Validate() error {
	if cfg.EnableAll {
		if cfg.DisableAll {
			return errors.New("enable-all and disable-all options must not be combined")
		}

		if len(cfg.EnabledCheckers) != 0 {
			return errors.New("enable-all and enable options must not be combined")
		}
	}

	if cfg.DisableAll {
		if len(cfg.DisabledCheckers) != 0 {
			return errors.New("disable-all and disable options must not be combined")
		}

		if len(cfg.EnabledCheckers) == 0 {
			return errors.New("all checkers were disabled, but no one checker was enabled: at least one must be enabled")
		}
	}

	for _, checker := range cfg.DisabledCheckers {
		if cfg.EnabledCheckers.Contains(checker) {
			return fmt.Errorf("checker %q disabled and enabled at one moment", checker)
		}
	}

	return nil
}

// BindToFlags binds Config fields to according flags.
func BindToFlags(cfg *Config, fs *flag.FlagSet) {
	fs.BoolVar(&cfg.EnableAll, "enable-all", false, "enable all checkers")
	fs.Var(&cfg.DisabledCheckers, "disable", "comma separated list of disabled checkers (to exclude from enabled by default)")
	fs.BoolVar(&cfg.DisableAll, "disable-all", false, "disable all checkers")
	fs.Var(&cfg.EnabledCheckers, "enable", "comma separated list of enabled checkers (in addition to enabled by default)")

	fs.Var(&cfg.ExpectedActual.ExpVarPattern, "expected-actual.pattern", "regexp for expected variable name")
	fs.Var(&cfg.RequireError.FnPattern, "require-error.fn-pattern", "regexp for error assertions that should only be analyzed")
	fs.Var(NewEnumValue(suiteExtraAssertCallModeAsString, &cfg.SuiteExtraAssertCall.Mode),
		"suite-extra-assert-call.mode", "to require or remove extra Assert() call")
}

var suiteExtraAssertCallModeAsString = map[string]checkers.SuiteExtraAssertCallMode{
	"remove":  checkers.SuiteExtraAssertCallModeRemove,
	"require": checkers.SuiteExtraAssertCallModeRequire,
}
