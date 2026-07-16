// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package validator provides input validation, pattern matching, and access control validation functions.
package validator

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/coveragedb"
)

type Result struct {
	Ok  bool
	Err error
}

// ResultOk is a predefined Result indicating success.
var ResultOk = Result{true, nil}

func AnyError(errPrefix string, results ...Result) error {
	for _, res := range results {
		if !res.Ok {
			return wrapError(res.Err.Error(), errPrefix)
		}
	}
	return nil
}

func AnyOk(results ...Result) Result {
	if len(results) == 0 {
		return ResultOk
	}
	for _, res := range results {
		if res.Ok {
			return ResultOk
		}
	}
	return results[0]
}

func PanicIfNot(results ...Result) error {
	if err := AnyError("", results...); err != nil {
		panic(err.Error())
	}
	return nil
}

var errValueNotAllowed = errors.New("value is not allowed")

func Allowlisted(str string, allowlist []string, valueName ...string) Result {
	if slices.Contains(allowlist, str) {
		return Result{
			Ok: true,
		}
	}
	if len(valueName) == 0 {
		return Result{
			Err: fmt.Errorf("value %s is not allowed", str),
		}
	}
	return Result{
		Err: fmt.Errorf("%s(%s) is not allowed", valueName[0], str),
	}
}

var (
	// EmptyStr validates that a string is empty.
	EmptyStr       = makeStrLenFunc("not empty", 0)
	// AlphaNumeric validates that a string contains only alphanumeric characters.
	AlphaNumeric   = makeStrReFunc("not an alphanum", "^[a-zA-Z0-9]*$")
	// CommitHash validates that a string is a valid git commit hash (40-char hex).
	CommitHash     = makeCombinedStrFunc("not a hash", AlphaNumeric, makeStrLenFunc("len is not 40", 40))
	// KernelFilePath validates that a string is a valid kernel file path.
	KernelFilePath = makeStrReFunc("not a kernel file path", "^[./_a-zA-Z0-9-]*$")
	// NamespaceName validates that a string is a valid namespace name.
	NamespaceName  = makeStrReFunc("not a namespace name", "^[a-zA-Z0-9_.-]{4,32}$")
	// ManagerName validates that a string is a valid manager name.
	ManagerName    = makeStrReFunc("not a manager name", "^[a-z0-9-]*$")
	// DashClientName validates that a string is a valid dashboard client name.
	DashClientName = makeStrReFunc("not a dashboard client name", "^[a-zA-Z0-9_.-]{4,100}$")
	// DashClientKey validates that a string is a valid dashboard client key.
	DashClientKey  = makeStrReFunc("not a dashboard client key",
		"^([a-zA-Z0-9]{16,128})|("+regexp.QuoteMeta(auth.OauthMagic)+".*)$")
	// TimePeriodType validates that a string is a valid time period type.
	TimePeriodType = makeStrReFunc(fmt.Sprintf("bad time period, use (%s|%s|%s)",
		coveragedb.DayPeriod, coveragedb.MonthPeriod, coveragedb.QuarterPeriod),
		fmt.Sprintf("^(%s|%s|%s)$", coveragedb.DayPeriod, coveragedb.MonthPeriod, coveragedb.QuarterPeriod))
)

type strValidationFunc func(string, ...string) Result

func looksDangerous(s string) bool {
	return strings.Contains(s, "--")
}

func makeStrReFunc(errStr, reStr string) strValidationFunc {
	matchRe := regexp.MustCompile(reStr)
	return func(s string, objName ...string) Result {
		if s == "" {
			return Result{false, wrapError(errStr + ": can't be empty")}
		}
		if looksDangerous(s) || !matchRe.MatchString(s) {
			return Result{false, wrapError(errStr, objName...)}
		}
		return ResultOk
	}
}

func makeStrLenFunc(errStr string, l int) strValidationFunc {
	return func(s string, objName ...string) Result {
		if len(s) != l {
			return Result{false, wrapError(errStr, objName...)}
		}
		return ResultOk
	}
}

func makeCombinedStrFunc(errStr string, funcs ...strValidationFunc) strValidationFunc {
	return func(s string, objName ...string) Result {
		for _, f := range funcs {
			if res := f(s); !res.Ok {
				return Result{false, wrapError(fmt.Sprintf(errStr+": %s", res.Err.Error()), objName...)}
			}
		}
		return ResultOk
	}
}

func wrapError(errStr string, prefix ...string) error {
	if len(prefix) > 0 && prefix[0] != "" {
		return fmt.Errorf("%s: %s", prefix[0], errStr)
	}
	return errors.New(errStr)
}
