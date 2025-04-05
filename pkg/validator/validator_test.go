// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package validator_test

import (
	"errors"
	"testing"

	"github.com/google/syzkaller/pkg/validator"
	"github.com/stretchr/testify/assert"
)

func TestIsCommitHash(t *testing.T) {
	assert.True(t, validator.CommitHash("b311c1b497e51a628aa89e7cb954481e5f9dced2").Ok)
	assert.False(t, validator.CommitHash("").Ok)
	assert.False(t, validator.CommitHash("b311").Ok)
	assert.False(t, validator.CommitHash("+311c1b497e51a628aa89e7cb954481e5f9dced2").Ok)

	assert.Equal(t, "not a hash: len is not 40", validator.CommitHash("b311").Err.Error())
	assert.Equal(t, "valName: not a hash: len is not 40",
		validator.CommitHash("b311", "valName").Err.Error())
	assert.Equal(t, "valName: not a hash: not an alphanum",
		validator.CommitHash("!311c1b497e51a628aa89e7cb954481e5f9dced2", "valName").Err.Error())
}

// nolint: dupl
func TestIsNamespaceName(t *testing.T) {
	assert.True(t, validator.NamespaceName("upstream").Ok)
	assert.False(t, validator.NamespaceName("up").Ok)
	assert.False(t, validator.NamespaceName("").Ok)

	assert.Equal(t, "not a namespace name", validator.NamespaceName("up").Err.Error())
	assert.Equal(t, "ns: not a namespace name",
		validator.NamespaceName("up", "ns").Err.Error())
}

// nolint: dupl
func TestIsManagerName(t *testing.T) {
	assert.True(t, validator.ManagerName("ci-upstream").Ok)
	assert.False(t, validator.ManagerName("").Ok)

	assert.Equal(t, "not a manager name", validator.ManagerName("*").Err.Error())
	assert.Equal(t, "manager: not a manager name",
		validator.ManagerName("*", "manager").Err.Error())
}

// nolint: dupl
func TestIsDashboardClientName(t *testing.T) {
	assert.True(t, validator.DashClientName("name").Ok)
	assert.False(t, validator.DashClientName("").Ok)

	assert.Equal(t, "not a dashboard client name", validator.DashClientName("cl").Err.Error())
	assert.Equal(t, "client: not a dashboard client name",
		validator.DashClientName("cl", "client").Err.Error())
}

// nolint: dupl
func TestIsDashboardClientKey(t *testing.T) {
	assert.True(t, validator.DashClientKey("b311c1b497e51a628aa89e7cb954481e5f9dced2").Ok)
	assert.False(t, validator.DashClientKey("").Ok)

	assert.Equal(t, "not a dashboard client key", validator.DashClientKey("key").Err.Error())
	assert.Equal(t, "clientKey: not a dashboard client key",
		validator.DashClientKey("clKey", "clientKey").Err.Error())
}

// nolint: dupl
func TestIsKernelFilePath(t *testing.T) {
	assert.True(t, validator.KernelFilePath("io_uring/advise.c").Ok)
	assert.True(t, validator.KernelFilePath("io-uring/advise.c").Ok)
	assert.False(t, validator.KernelFilePath("io--uring/advise.c").Ok)
	assert.False(t, validator.KernelFilePath("").Ok)

	assert.Equal(t, "not a kernel file path", validator.KernelFilePath("io--uring").Err.Error())
	assert.Equal(t, "kernelPath: not a kernel file path",
		validator.KernelFilePath("io--uring", "kernelPath").Err.Error())
}

var badResult = validator.Result{false, errors.New("sample error")}

func TestAnyError(t *testing.T) {
	assert.Nil(t, validator.AnyError("prefix", validator.ResultOk, validator.ResultOk))
	assert.Equal(t, "prefix: sample error",
		validator.AnyError("prefix", validator.ResultOk, badResult).Error())
}

func TestPanicIfNot(t *testing.T) {
	assert.NotPanics(t, func() { validator.PanicIfNot(validator.ResultOk, validator.ResultOk) })
	assert.Panics(t, func() { validator.PanicIfNot(validator.ResultOk, badResult) })
}

func TestAnyOk(t *testing.T) {
	assert.Equal(t, validator.ResultOk, validator.AnyOk())
	assert.Equal(t, validator.ResultOk, validator.AnyOk(validator.ResultOk))
	assert.Equal(t, badResult, validator.AnyOk(badResult))
	assert.Equal(t, validator.ResultOk, validator.AnyOk(badResult, validator.ResultOk))
}

func TestAllowlisted(t *testing.T) {
	assert.True(t, validator.Allowlisted("good", []string{"good", "also-good"}).Ok)
	assert.False(t, validator.Allowlisted("bad", []string{"good", "also-good"}).Ok)
	assert.Equal(t,
		validator.Result{Ok: false, Err: errors.New("name(bad) is not allowed")},
		validator.Allowlisted("bad", nil, "name"))
}
