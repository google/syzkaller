// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-testbed automatically checks out, builds and sets up a number of syzkaller instances.
// This might be very helpful e.g. when gauging the effect of new changes on the total syzkaller
// performance.
// For details see docs/syz_testbed.md.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig = flag.String("config", "", "config file")
)

type TestbedConfig struct {
	Name          string           `json:"name"`           // name of the testbed
	Target        string           `json:"target"`         // what application to test
	MaxInstances  int              `json:"max_instances"`  // max # of simultaneously running instances
	RunTime       DurationConfig   `json:"run_time"`       // lifetime of an instance (default "24h")
	HTTP          string           `json:"http"`           // on which port to set up a simple web dashboard
	BenchCmp      string           `json:"benchcmp"`       // path to the syz-benchcmp executable
	Corpus        string           `json:"corpus"`         // path to the corpus file
	Workdir       string           `json:"workdir"`        // instances will be checked out there
	ReproConfig   ReproTestConfig  `json:"repro_config"`   // syz-repro benchmarking config
	ManagerConfig json.RawMessage  `json:"manager_config"` // base manager config
	ManagerMode   string           `json:"manager_mode"`   // manager mode flag
	Checkouts     []CheckoutConfig `json:"checkouts"`
}

type DurationConfig struct {
	time.Duration
}

type CheckoutConfig struct {
	Name          string          `json:"name"`
	Repo          string          `json:"repo"`
	Branch        string          `json:"branch"`
	ManagerConfig json.RawMessage `json:"manager_config"` // a patch to manager config
}

type ReproTestConfig struct {
	InputLogs     string   `json:"input_logs"`      // take crash logs from a folder
	InputWorkdir  string   `json:"input_workdir"`   // take crash logs from a syzkaller's workdir
	CrashesPerBug int      `json:"crashes_per_bug"` // how many crashes must be taken from each bug
	SkipBugs      []string `json:"skip_bugs"`       // crashes to exclude from the workdir, list of regexps
}

type TestbedContext struct {
	Config         *TestbedConfig
	Checkouts      []*Checkout
	NextCheckoutID int
	NextInstanceID int
	Target         TestbedTarget
	mu             sync.Mutex
}

func main() {
	flag.Parse()
	benchcmp, _ := exec.LookPath("syz-benchcmp")
	cfg := &TestbedConfig{
		Name:     "testbed",
		Target:   "syz-manager",
		BenchCmp: benchcmp,
		RunTime:  DurationConfig{24 * time.Hour},
		ReproConfig: ReproTestConfig{
			CrashesPerBug: 1,
		},
		ManagerMode: "fuzzing",
	}
	err := config.LoadFile(*flagConfig, &cfg)
	if err != nil {
		tool.Failf("failed to read config: %s", err)
	}

	err = checkConfig(cfg)
	if err != nil {
		tool.Failf("invalid config: %s", err)
	}
	ctx := TestbedContext{
		Config: cfg,
		Target: targetConstructors[cfg.Target](cfg),
	}
	go ctx.setupHTTPServer()

	for _, checkoutCfg := range cfg.Checkouts {
		mgrCfg := ctx.MakeMgrConfig(cfg.ManagerConfig, checkoutCfg.ManagerConfig)
		co, err := ctx.NewCheckout(&checkoutCfg, mgrCfg)
		if err != nil {
			tool.Failf("checkout failed: %s", err)
		}
		ctx.Checkouts = append(ctx.Checkouts, co)
	}

	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)

	go func() {
		const period = 90 * time.Second
		for {
			time.Sleep(period)
			err := ctx.SaveStats()
			if err != nil {
				log.Printf("stats saving error: %s", err)
			}
		}
	}()

	ctx.Loop(shutdown)
}

func (ctx *TestbedContext) MakeMgrConfig(base, patch json.RawMessage) json.RawMessage {
	mgrCfg, err := config.MergeJSONs(base, patch)
	if err != nil {
		tool.Failf("failed to apply a patch to the base manager config: %s", err)
	}
	// We don't care much about the specific ports of syz-managers.
	mgrCfg, err = config.PatchJSON(mgrCfg, map[string]interface{}{"HTTP": ":0"})
	if err != nil {
		tool.Failf("failed to assign empty HTTP value: %s", err)
	}
	return mgrCfg
}

func (ctx *TestbedContext) GetStatViews() ([]StatView, error) {
	groupsCompleted := []RunResultGroup{}
	groupsAll := []RunResultGroup{}
	for _, checkout := range ctx.Checkouts {
		running := checkout.GetRunningResults()
		completed := checkout.GetCompletedResults()
		groupsCompleted = append(groupsCompleted, RunResultGroup{
			Name:    checkout.Name,
			Results: completed,
		})
		groupsAll = append(groupsAll, RunResultGroup{
			Name:    checkout.Name,
			Results: append(completed, running...),
		})
	}
	return []StatView{
		{
			Name:   "completed",
			Groups: groupsCompleted,
		},
		{
			Name:   "all",
			Groups: groupsAll,
		},
	}, nil
}

func (ctx *TestbedContext) TestbedStatsTable() *Table {
	table := NewTable("Checkout", "Running", "Completed", "Last started")
	for _, checkout := range ctx.Checkouts {
		checkout.mu.Lock()
		last := ""
		if !checkout.LastRunning.IsZero() {
			last = time.Since(checkout.LastRunning).Round(time.Second).String()
		}
		table.AddRow(checkout.Name,
			fmt.Sprintf("%d", len(checkout.Running)),
			fmt.Sprintf("%d", len(checkout.Completed)),
			last,
		)
		checkout.mu.Unlock()
	}
	return table
}

func (ctx *TestbedContext) SaveStats() error {
	// Preventing concurrent saving of the stats.
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	views, err := ctx.GetStatViews()
	if err != nil {
		return err
	}
	for _, view := range views {
		dir := filepath.Join(ctx.Config.Workdir, "stats_"+view.Name)
		err := ctx.Target.SaveStatView(view, dir)
		if err != nil {
			return err
		}
	}
	table := ctx.TestbedStatsTable()
	return table.SaveAsCsv(filepath.Join(ctx.Config.Workdir, "testbed.csv"))
}

func (ctx *TestbedContext) Slot(slotID int, stop chan struct{}, ret chan error) {
	// It seems that even gracefully finished syz-managers can leak GCE instances.
	// To allow for that strange behavior, let's reuse syz-manager names in each slot,
	// so that its VMs will in turn reuse the names of the leaked ones.
	slotName := fmt.Sprintf("%s-%d", ctx.Config.Name, slotID)
	for {
		checkout, instance, err := ctx.Target.NewJob(slotName, ctx.Checkouts)
		if err != nil {
			ret <- fmt.Errorf("failed to create instance: %w", err)
			return
		}
		checkout.AddRunning(instance)
		retChannel := make(chan error)
		go func() {
			retChannel <- instance.Run()
		}()

		var retErr error
		select {
		case <-stop:
			instance.Stop()
			<-retChannel
			retErr = fmt.Errorf("instance was killed")
		case retErr = <-retChannel:
		}

		// For now, we only archive instances that finished normally (ret == nil).
		// syz-testbed will anyway stop after such an error, so it's not a problem
		// that they remain in Running.
		if retErr != nil {
			ret <- retErr
			return
		}
		err = checkout.ArchiveInstance(instance)
		if err != nil {
			ret <- fmt.Errorf("a call to ArchiveInstance failed: %w", err)
			return
		}
	}
}

// Create instances, run them, stop them, archive them, and so on...
func (ctx *TestbedContext) Loop(stop chan struct{}) {
	stopAll := make(chan struct{})
	errors := make(chan error)
	for i := 0; i < ctx.Config.MaxInstances; i++ {
		go ctx.Slot(i, stopAll, errors)
	}

	exited := 0
	select {
	case <-stop:
		log.Printf("stopping the experiment")
	case err := <-errors:
		exited = 1
		log.Printf("an instance has failed (%s), stopping everything", err)
	}
	close(stopAll)
	for ; exited < ctx.Config.MaxInstances; exited++ {
		<-errors
	}
}

func (d *DurationConfig) UnmarshalJSON(data []byte) error {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s was expected to be a string", data)
	}
	parsed, err := time.ParseDuration(str)
	if err == nil {
		d.Duration = parsed
	}
	return err
}

func (d *DurationConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func checkReproTestConfig(cfg *ReproTestConfig) error {
	if cfg.InputLogs != "" && !osutil.IsExist(cfg.InputLogs) {
		return fmt.Errorf("input_log folder does not exist: %v", cfg.InputLogs)
	}
	if cfg.InputWorkdir != "" && !osutil.IsExist(cfg.InputWorkdir) {
		return fmt.Errorf("input_workdir folder does not exist: %v", cfg.InputWorkdir)
	}
	if cfg.CrashesPerBug < 1 {
		return fmt.Errorf("crashes_per_bug cannot be less than 1: %d", cfg.CrashesPerBug)
	}
	return nil
}

func checkConfig(cfg *TestbedConfig) error {
	testbedNameRe := regexp.MustCompile(`^[0-9a-z\-]{1,20}$`)
	if !testbedNameRe.MatchString(cfg.Name) {
		return fmt.Errorf("invalid testbed name: %v", cfg.Name)
	}
	if cfg.Workdir == "" {
		return fmt.Errorf("workdir is empty")
	}
	cfg.Workdir = osutil.Abs(cfg.Workdir)
	err := osutil.MkdirAll(cfg.Workdir)
	if err != nil {
		return err
	}
	if cfg.Corpus != "" && !osutil.IsExist(cfg.Corpus) {
		return fmt.Errorf("corpus %v does not exist", cfg.Corpus)
	}
	if cfg.MaxInstances < 1 {
		return fmt.Errorf("max_instances cannot be less than 1")
	}
	if cfg.BenchCmp != "" && !osutil.IsExist(cfg.BenchCmp) {
		return fmt.Errorf("benchmp path is specified, but %s does not exist", cfg.BenchCmp)
	}
	if _, ok := targetConstructors[cfg.Target]; !ok {
		return fmt.Errorf("unknown target %s", cfg.Target)
	}
	if err = checkReproTestConfig(&cfg.ReproConfig); err != nil {
		return err
	}
	cfg.Corpus = osutil.Abs(cfg.Corpus)
	names := make(map[string]bool)
	for idx := range cfg.Checkouts {
		co := &cfg.Checkouts[idx]
		if !vcs.CheckRepoAddress(co.Repo) {
			return fmt.Errorf("invalid repo: %s", co.Repo)
		}
		if co.Branch == "" {
			co.Branch = "master"
		} else if !vcs.CheckBranch(co.Branch) {
			return fmt.Errorf("invalid branch: %s", co.Branch)
		}
		if names[co.Name] {
			return fmt.Errorf("duplicate checkout name: %v", co.Name)
		}
		names[co.Name] = true
	}
	return nil
}
