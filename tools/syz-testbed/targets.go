// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/osutil"
)

// TestbedTarget represents all behavioral differences between specific testbed targets.
type TestbedTarget interface {
	NewJob(slotName string, checkouts []*Checkout) (*Checkout, Instance, error)
	SaveStatView(view StatView, dir string) error
	SupportsHTMLView(key string) bool
}

type SyzManagerTarget struct {
	config         *TestbedConfig
	nextCheckoutID int
	nextInstanceID int
	mu             sync.Mutex
}

var targetConstructors = map[string]func(cfg *TestbedConfig) TestbedTarget{
	"syz-manager": func(cfg *TestbedConfig) TestbedTarget {
		return &SyzManagerTarget{
			config: cfg,
		}
	},
}

func (t *SyzManagerTarget) NewJob(slotName string, checkouts []*Checkout) (*Checkout, Instance, error) {
	// Round-robin strategy should suffice.
	t.mu.Lock()
	checkout := checkouts[t.nextCheckoutID%len(checkouts)]
	instanceID := t.nextInstanceID
	t.nextCheckoutID++
	t.nextInstanceID++
	t.mu.Unlock()
	uniqName := fmt.Sprintf("%s-%d", checkout.Name, instanceID)
	instance, err := t.newSyzManagerInstance(slotName, uniqName, checkout)
	if err != nil {
		return nil, nil, err
	}
	return checkout, instance, nil
}

func (t *SyzManagerTarget) SupportsHTMLView(key string) bool {
	supported := map[string]bool{
		HTMLBugsTable:      true,
		HTMLBugCountsTable: true,
		HTMLStatsTable:     true,
	}
	return supported[key]
}

func (t *SyzManagerTarget) SaveStatView(view StatView, dir string) error {
	benchDir := filepath.Join(dir, "benches")
	err := osutil.MkdirAll(benchDir)
	if err != nil {
		return fmt.Errorf("failed to create %s: %s", benchDir, err)
	}
	tableStats := map[string]func(view StatView) (*Table, error){
		"bugs.csv":           (StatView).GenerateBugTable,
		"checkout_stats.csv": (StatView).StatsTable,
		"instance_stats.csv": (StatView).InstanceStatsTable,
	}
	for fileName, genFunc := range tableStats {
		table, err := genFunc(view)
		if err == nil {
			table.SaveAsCsv(filepath.Join(dir, fileName))
		} else {
			log.Printf("stat generation error: %s", err)
		}
	}
	_, err = view.SaveAvgBenches(benchDir)
	return err
}
