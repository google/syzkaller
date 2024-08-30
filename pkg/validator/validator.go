// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package validator

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/coveragedb"
)

type Result struct {
	Ok  bool
	Err error
}

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

var (
	EmptyStr       = makeStrLenFunc("not empty", 0)
	AlphaNumeric   = makeStrReFunc("not an alphanum", "^[a-zA-Z0-9]*$")
	CommitHash     = makeCombinedStrFunc("not a hash", AlphaNumeric, makeStrLenFunc("len is not 40", 40))
	KernelFilePath = makeStrReFunc("not a kernel file path", "^[./-_a-zA-Z0-9]*$")
	NamespaceName  = makeStrReFunc("not a namespace name", "^[a-zA-Z0-9-_.]{4,32}$")
	DashClientName = makeStrReFunc("not a dashboard client name", "^[a-zA-Z0-9-_.]{4,100}$")
	DashClientKey  = makeStrReFunc("not a dashboard client key",
		"^([a-zA-Z0-9]{16,128})|("+regexp.QuoteMeta(auth.OauthMagic)+".*)$")
	TimePeriodType = makeStrReFunc(fmt.Sprintf("bad time period, use (%s|%s|%s)",
		coveragedb.DayPeriod, coveragedb.MonthPeriod, coveragedb.QuarterPeriod),
		fmt.Sprintf("^(%s|%s|%s)$", coveragedb.DayPeriod, coveragedb.MonthPeriod, coveragedb.QuarterPeriod))
)

type strValidationFunc func(string, ...string) Result

func makeStrReFunc(errStr, reStr string) strValidationFunc {
	matchRe := regexp.MustCompile(reStr)
	return func(s string, objName ...string) Result {
		if !matchRe.MatchString(s) {
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
