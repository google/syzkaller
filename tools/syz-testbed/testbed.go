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
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig = flag.String("config", "", "config file")
)

type TestbedConfig struct {
	Name          string           `json:"name"`           // name of the testbed
	MaxInstances  int              `json:"max_instances"`  // max # of simultaneously running instances
	RunTime       DurationConfig   `json:"run_time"`       // lifetime of an instance (default "24h")
	HTTP          string           `json:"http"`           // on which port to set up a simple web dashboard
	BenchCmp      string           `json:"benchcmp"`       // path to the syz-benchcmp executable
	Corpus        string           `json:"corpus"`         // path to the corpus file
	Workdir       string           `json:"workdir"`        // instances will be checked out there
	ManagerConfig json.RawMessage  `json:"manager_config"` // base manager config
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

type TestbedContext struct {
	Config         *TestbedConfig
	Checkouts      []*Checkout
	NextRestart    time.Time
	NextCheckoutID int
	NextInstanceID int
	statMutex      sync.Mutex
}

func main() {
	flag.Parse()
	cfg := &TestbedConfig{
		Name:    "testbed",
		RunTime: DurationConfig{24 * time.Hour},
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

func (ctx *TestbedContext) MakeMgrConfig(base, patch json.RawMessage) *mgrconfig.Config {
	mergedConfig, err := config.MergeJSONData(base, patch)
	if err != nil {
		tool.Failf("failed to apply a patch to the base manager config: %s", err)
	}
	mgrCfg, err := mgrconfig.LoadPartialData(mergedConfig)
	if err != nil {
		tool.Failf("failed to parse base manager config: %s", err)
	}
	if mgrCfg.HTTP == "" {
		// Actually, we don't care much about the specific ports of syz-managers.
		mgrCfg.HTTP = ":0"
	}
	return mgrCfg
}

func (ctx *TestbedContext) GetStatViews() ([]StatView, error) {
	groupsCompleted := []RunResultGroup{}
	groupsAll := []RunResultGroup{}
	for _, checkout := range ctx.Checkouts {
		running := []*RunResult{}
		for _, instance := range checkout.Running {
			result, err := instance.FetchResult()
			if err != nil {
				return nil, err
			}
			running = append(running, result)
		}
		groupsCompleted = append(groupsCompleted, RunResultGroup{
			Name:    checkout.Name,
			Results: checkout.Completed,
		})
		groupsAll = append(groupsAll, RunResultGroup{
			Name:    checkout.Name,
			Results: append(checkout.Completed, running...),
		})
	}
	return []StatView{
		{
			Name:   "all",
			Groups: groupsAll,
		},
		{
			Name:   "completed",
			Groups: groupsCompleted,
		},
	}, nil
}

func (ctx *TestbedContext) saveStatView(view StatView) error {
	dir := filepath.Join(ctx.Config.Workdir, "stats_"+view.Name)
	benchDir := filepath.Join(dir, "benches")
	err := osutil.MkdirAll(benchDir)
	if err != nil {
		return fmt.Errorf("failed to create %s: %s", benchDir, err)
	}

	tableStats := map[string]func(view StatView) ([][]string, error){
		"bugs.csv":           (StatView).GenerateBugTable,
		"checkout_stats.csv": (StatView).StatsTable,
		"instance_stats.csv": (StatView).InstanceStatsTable,
	}
	for fileName, genFunc := range tableStats {
		table, err := genFunc(view)
		if err == nil {
			SaveTableAsCsv(table, filepath.Join(dir, fileName))
		} else {
			log.Printf("some error: %s", err)
		}
	}
	_, err = view.SaveAvgBenches(benchDir)
	return err
}

func (ctx *TestbedContext) TestbedStatsTable() [][]string {
	table := [][]string{
		{"Checkout", "Running", "Completed", "Until reset"},
	}
	for _, checkout := range ctx.Checkouts {
		until := "-"
		if ctx.NextRestart.After(time.Now()) {
			until = time.Until(ctx.NextRestart).Round(time.Second).String()
		}
		table = append(table, []string{
			checkout.Name,
			fmt.Sprintf("%d", len(checkout.Running)),
			fmt.Sprintf("%d", len(checkout.Completed)),
			until,
		})
	}
	return table
}

func (ctx *TestbedContext) SaveStats() error {
	// Preventing concurrent saving of the stats.
	ctx.statMutex.Lock()
	defer ctx.statMutex.Unlock()
	views, err := ctx.GetStatViews()
	if err != nil {
		return err
	}
	for _, view := range views {
		err := ctx.saveStatView(view)
		if err != nil {
			return err
		}
	}
	table := ctx.TestbedStatsTable()
	return SaveTableAsCsv(table, filepath.Join(ctx.Config.Workdir, "testbed.csv"))
}

func (ctx *TestbedContext) generateInstances(count int) ([]*Instance, error) {
	// It seems that even gracefully finished syz-managers can leak GCE instances.
	// To allow for that strange behavior, let's reuse syz-manager names, so that
	// they will in turn reuse the names of the leaked GCE instances.
	instances := []*Instance{}
	for idx := 1; idx <= count; idx++ {
		checkout := ctx.Checkouts[ctx.NextCheckoutID]
		ctx.NextCheckoutID = (ctx.NextCheckoutID + 1) % len(ctx.Checkouts)
		instance, err := ctx.NewInstance(checkout, fmt.Sprintf("%s-%d", ctx.Config.Name, idx))
		if err != nil {
			return nil, err
		}
		checkout.Running = append(checkout.Running, instance)
		instances = append(instances, instance)
	}
	return instances, nil
}

// Create instances, run them, stop them, archive them, and so on...
func (ctx *TestbedContext) Loop(stop chan struct{}) {
	duration := ctx.Config.RunTime.Duration
	mustStop := false
	for !mustStop {
		log.Printf("setting up instances")
		instances, err := ctx.generateInstances(ctx.Config.MaxInstances)
		if err != nil {
			tool.Failf("failed to set up intances: %s", err)
		}
		log.Printf("starting instances")
		instanceStatuses := make(chan error, len(instances))
		var wg sync.WaitGroup
		for _, inst := range instances {
			wg.Add(1)
			go func(instance *Instance) {
				instanceStatuses <- instance.Run()
				wg.Done()
			}(inst)
		}

		ctx.NextRestart = time.Now().Add(duration)
		select {
		case err := <-instanceStatuses:
			// Syz-managers are not supposed to stop under normal circumstances.
			// If one of them did stop, there must have been a very good reason to.
			// For now, we just shut down the whole experiment in such a case.
			log.Printf("an instance has failed (%s), stopping everything", err)
			mustStop = true
		case <-stop:
			log.Printf("stopping the experiment")
			mustStop = true
		case <-time.After(duration):
			log.Printf("run period has finished")
		}

		// Wait for all instances to finish.
		for _, instance := range instances {
			instance.Stop()
		}
		wg.Wait()

		// Only mark instances completed if they've indeed been running the whole iteration.
		if !mustStop {
			for _, checkout := range ctx.Checkouts {
				err = checkout.ArchiveRunning()
				if err != nil {
					tool.Failf("ArchiveRunning error: %s", err)
				}
			}
		}

		log.Printf("collecting statistics")
		err = ctx.SaveStats()
		if err != nil {
			log.Printf("stats saving error: %s", err)
		}
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
