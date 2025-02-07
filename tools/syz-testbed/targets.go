// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
)

// TestbedTarget represents all behavioral differences between specific testbed targets.
type TestbedTarget interface {
	NewJob(slotName string, checkouts []*Checkout) (*Checkout, Instance, error)
	SaveStatView(view *StatView, dir string) error
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
	"syz-repro": func(cfg *TestbedConfig) TestbedTarget {
		inputFiles := []string{}
		reproConfig := cfg.ReproConfig
		if reproConfig.InputLogs != "" {
			err := filepath.WalkDir(reproConfig.InputLogs, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !d.IsDir() {
					inputFiles = append(inputFiles, path)
				}
				return nil
			})
			if err != nil {
				tool.Failf("failed to read logs file directory: %s", err)
			}
		} else if reproConfig.InputWorkdir != "" {
			skipRegexps := []*regexp.Regexp{}
			for _, reStr := range reproConfig.SkipBugs {
				skipRegexps = append(skipRegexps, regexp.MustCompile(reStr))
			}
			bugs, err := collectBugs(reproConfig.InputWorkdir)
			if err != nil {
				tool.Failf("failed to read workdir: %s", err)
			}
			r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
			for _, bug := range bugs {
				skip := false
				for _, re := range skipRegexps {
					if re.MatchString(bug.Title) {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
				logs := append([]string{}, bug.Logs...)
				for i := 0; i < reproConfig.CrashesPerBug && len(logs) > 0; i++ {
					randID := r.Intn(len(logs))
					logs[len(logs)-1], logs[randID] = logs[randID], logs[len(logs)-1]
					inputFiles = append(inputFiles, logs[len(logs)-1])
					logs = logs[:len(logs)-1]
				}
			}
		}
		inputs := []*SyzReproInput{}
		log.Printf("picked up crash files:")
		for _, path := range inputFiles {
			log.Printf("- %s", path)
			inputs = append(inputs, &SyzReproInput{
				Path:  path,
				runBy: make(map[*Checkout]int),
			})
		}
		if len(inputs) == 0 {
			tool.Failf("no inputs given")
		}
		// TODO: shuffle?
		return &SyzReproTarget{
			config:     cfg,
			dedupTitle: make(map[string]int),
			inputs:     inputs,
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
	instance, err := t.newSyzManagerInstance(slotName, uniqName, t.config.ManagerMode, checkout)
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

func (t *SyzManagerTarget) SaveStatView(view *StatView, dir string) error {
	benchDir := filepath.Join(dir, "benches")
	err := osutil.MkdirAll(benchDir)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", benchDir, err)
	}
	tableStats := map[string]func(view *StatView) (*Table, error){
		"bugs.csv":           (*StatView).GenerateBugTable,
		"checkout_stats.csv": (*StatView).StatsTable,
		"instance_stats.csv": (*StatView).InstanceStatsTable,
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

// TODO: consider other repro testing modes.
// E.g. group different logs by title. Then we could also set different sets of inputs
// for each checkout. It can be important if we improve executor logging.
type SyzReproTarget struct {
	config     *TestbedConfig
	inputs     []*SyzReproInput
	seqID      int
	dedupTitle map[string]int
	mu         sync.Mutex
}

type SyzReproInput struct {
	Path      string
	Title     string
	Skip      bool
	origTitle string
	runBy     map[*Checkout]int
}

func (inp *SyzReproInput) QueryTitle(checkout *Checkout, dupsMap map[string]int) error {
	data, err := os.ReadFile(inp.Path)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}
	report := checkout.GetReporter().Parse(data)
	if report == nil {
		return fmt.Errorf("found no crash")
	}
	if inp.Title == "" {
		inp.origTitle = report.Title
		inp.Title = report.Title
		// Some bug titles may be present in multiple log files.
		// Ensure they are all distict to the user.
		dupsMap[inp.origTitle]++
		if dupsMap[inp.Title] > 1 {
			inp.Title += fmt.Sprintf(" (%d)", dupsMap[inp.origTitle])
		}
	}
	return nil
}

func (t *SyzReproTarget) NewJob(slotName string, checkouts []*Checkout) (*Checkout, Instance, error) {
	t.mu.Lock()
	seqID := t.seqID
	checkout := checkouts[t.seqID%len(checkouts)]
	t.seqID++
	// This may be not the most efficient algorithm, but it guarantees even distribution of
	// resources and CPU time is negligible in comparison with the amount of time each instance runs.
	var input *SyzReproInput
	for _, candidate := range t.inputs {
		if candidate.Skip {
			continue
		}
		if candidate.runBy[checkout] == 0 {
			// This is the first time we'll attempt to give this log to the checkout.
			// Check if it can handle it.
			err := candidate.QueryTitle(checkout, t.dedupTitle)
			if err != nil {
				log.Printf("[log %s]: %s, skipping", candidate.Path, err)
				candidate.Skip = true
				continue
			}
		}
		if input == nil || input.runBy[checkout] > candidate.runBy[checkout] {
			// Pick the least executed one.
			input = candidate
		}
	}

	if input == nil {
		t.mu.Unlock()
		return nil, nil, fmt.Errorf("no available inputs")
	}
	input.runBy[checkout]++
	t.mu.Unlock()

	uniqName := fmt.Sprintf("%s-%d", checkout.Name, seqID)
	instance, err := t.newSyzReproInstance(slotName, uniqName, input, checkout)
	if err != nil {
		return nil, nil, err
	}
	return checkout, instance, nil
}

func (t *SyzReproTarget) SupportsHTMLView(key string) bool {
	supported := map[string]bool{
		HTMLReprosTable:        true,
		HTMLCReprosTable:       true,
		HTMLReproAttemptsTable: true,
		HTMLReproDurationTable: true,
	}
	return supported[key]
}

func (t *SyzReproTarget) SaveStatView(view *StatView, dir string) error {
	tableStats := map[string]func(view *StatView) (*Table, error){
		"repro_success.csv":   (*StatView).GenerateReproSuccessTable,
		"crepros_success.csv": (*StatView).GenerateCReproSuccessTable,
		"repro_attempts.csv":  (*StatView).GenerateReproAttemptsTable,
		"repro_duration.csv":  (*StatView).GenerateReproDurationTable,
	}
	for fileName, genFunc := range tableStats {
		table, err := genFunc(view)
		if err == nil {
			table.SaveAsCsv(filepath.Join(dir, fileName))
		} else {
			log.Printf("stat generation error: %s", err)
		}
	}
	return nil
}
