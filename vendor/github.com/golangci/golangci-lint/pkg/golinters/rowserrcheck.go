package golinters

import (
	"github.com/jingyugao/rowserrcheck/passes/rowserr"
	"golang.org/x/tools/go/analysis"

	"github.com/golangci/golangci-lint/pkg/config"
	"github.com/golangci/golangci-lint/pkg/golinters/goanalysis"
)

func NewRowsErrCheck(settings *config.RowsErrCheckSettings) *goanalysis.Linter {
	var pkgs []string
	if settings != nil {
		pkgs = settings.Packages
	}

	a := rowserr.NewAnalyzer(pkgs...)

	return goanalysis.NewLinter(
		a.Name,
		"checks whether Rows.Err of rows is checked successfully",
		[]*analysis.Analyzer{a},
		nil,
	).WithLoadMode(goanalysis.LoadModeTypesInfo)
}
