package gomegainfo

import (
	"go/ast"
	gotypes "go/types"
	"regexp"

	"golang.org/x/tools/go/analysis"
)

const ( // gomega actual method names
	expect                 = "Expect"
	expectWithOffset       = "ExpectWithOffset"
	omega                  = "Ω"
	eventually             = "Eventually"
	eventuallyWithOffset   = "EventuallyWithOffset"
	consistently           = "Consistently"
	consistentlyWithOffset = "ConsistentlyWithOffset"
)

const ( // assertion methods
	to        = "To"
	toNot     = "ToNot"
	notTo     = "NotTo"
	should    = "Should"
	shouldNot = "ShouldNot"
)

var funcOffsetMap = map[string]int{
	expect:                 0,
	expectWithOffset:       1,
	omega:                  0,
	eventually:             0,
	eventuallyWithOffset:   1,
	consistently:           0,
	consistentlyWithOffset: 1,
}

func IsActualMethod(name string) bool {
	_, found := funcOffsetMap[name]
	return found
}

func ActualArgOffset(methodName string) int {
	funcOffset, ok := funcOffsetMap[methodName]
	if !ok {
		return -1
	}
	return funcOffset
}

func GetAllowedAssertionMethods(actualMethodName string) string {
	switch actualMethodName {
	case expect, expectWithOffset:
		return `"To()", "ToNot()" or "NotTo()"`

	case eventually, eventuallyWithOffset, consistently, consistentlyWithOffset:
		return `"Should()" or "ShouldNot()"`

	case omega:
		return `"Should()", "To()", "ShouldNot()", "ToNot()" or "NotTo()"`

	default:
		return ""
	}
}

var asyncFuncSet = map[string]struct{}{
	eventually:             {},
	eventuallyWithOffset:   {},
	consistently:           {},
	consistentlyWithOffset: {},
}

func IsAsyncActualMethod(name string) bool {
	_, ok := asyncFuncSet[name]
	return ok
}

func IsAssertionFunc(name string) bool {
	switch name {
	case to, toNot, notTo, should, shouldNot:
		return true
	}
	return false
}

var gomegaTypeRegex = regexp.MustCompile(`github\.com/onsi/gomega/(?:internal|types)\.Gomega`)

func IsGomegaVar(x ast.Expr, pass *analysis.Pass) bool {
	if tx, ok := pass.TypesInfo.Types[x]; ok {
		return IsGomegaType(tx.Type)
	}

	return false
}

func IsGomegaType(t gotypes.Type) bool {
	var typeStr string
	switch ttx := t.(type) {
	case *gotypes.Pointer:
		tp := ttx.Elem()
		typeStr = tp.String()

	case *gotypes.Named:
		typeStr = ttx.String()

	default:
		return false
	}

	return gomegaTypeRegex.MatchString(typeStr)
}
