// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package workflow

import (
	"sync"
	"time"
)

// It's assumed that the workflow will query the necessary data and report its detailed progress itself,
// so we only need to be able to start it and to check whether its current overall state.

type Service interface {
	Start(sessionID, seriesID string) error
	Status(id string) (Status, error)
	// The recommended value. May depend on the implementation (test/prod).
	PollPeriod() time.Duration
}

type Status string

const (
	StatusNotFound Status = "not_found"
	StatusRunning  Status = "running"
	StatusFinished Status = "finished"
	StatusFailed   Status = "failed"
)

// MockService serializes callback invokations to simplify test implementations.
type MockService struct {
	mu             sync.Mutex
	PollDelayValue time.Duration
	OnStart        func(string, string) error
	OnStatus       func(string) (Status, error)
}

func (ms *MockService) Start(id, id2 string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.OnStart != nil {
		return ms.OnStart(id, id2)
	}
	return nil
}

func (ms *MockService) Status(id string) (Status, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.OnStatus != nil {
		return ms.OnStatus(id)
	}
	return StatusNotFound, nil
}

func (ms *MockService) PollPeriod() time.Duration {
	return ms.PollDelayValue
}
