// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-testbed automatically checks out, builds and sets up a number of syzkaller instances.
// This might be very helpful e.g. when gauging the effect of new changes on the total syzkaller
// performance.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/config"
	syz_instance "github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig  = flag.String("config", "", "config file")
	flagCleanup = flag.Bool("cleanup", false, "remove existing work directories")
)

type TestbedConfig struct {
	Corpus        string            `json:"corpus"`         // path to the corpus file
	Workdir       string            `json:"workdir"`        // instances will be checked out there
	ManagerConfig json.RawMessage   `json:"manager_config"` // base manager config
	Checkouts     []TestbedCheckout `json:"checkouts"`
}

type TestbedCheckout struct {
	Name   string `json:"name"`
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	Count  int    `json:"count"`
}

type CheckoutInfo struct {
	Path      string
	Name      string
	Instances []InstanceInfo
}

// The essential information about an already prepared instance.
type InstanceInfo struct {
	Name            string
	Workdir         string
	BenchFile       string
	LogFile         string
	HTTP            string
	ExecCommand     string
	ExecCommandArgs []string
}

func main() {
	flag.Parse()
	cfg := &TestbedConfig{}
	err := config.LoadFile(*flagConfig, &cfg)
	if err != nil {
		tool.Failf("failed to read config: %s", err)
	}

	err = checkConfig(cfg)
	if err != nil {
		tool.Failf("invalid config: %s", err)
	}

	managerCfg, err := mgrconfig.LoadPartialData(cfg.ManagerConfig)
	if err != nil {
		tool.Failf("failed to parse manager config: %s", err)
	}
	if managerCfg.HTTP == "" {
		managerCfg.HTTP = ":50000"
	}

	checkouts := []*CheckoutInfo{}
	for _, co := range cfg.Checkouts {
		checkouts = append(checkouts, newCheckout(co, cfg, managerCfg))
	}

	log.Printf("------------------")
	for _, co := range checkouts {
		for _, instance := range co.Instances {
			go runInstance(instance)
		}
	}
	go collectStats(cfg, checkouts)
	// Block the execution indefinitely.
	// Either the process will be killed or it will exit itself if one of the instances fails.
	select {}
}

func collectStats(cfg *TestbedConfig, checkouts []*CheckoutInfo) {
	const period = 90 * time.Second
	benchFolder := filepath.Join(cfg.Workdir, "benches")
	err := osutil.MkdirAll(benchFolder)
	if err != nil {
		tool.Failf("failed to create bench folder: %s", err)
	}
	tableStats := map[string]func(checkouts []*CheckoutInfo) ([][]string, error){
		"bugs.csv":           generateBugTable,
		"checkout_stats.csv": checkoutStatsTable,
		"instance_stats.csv": instanceStatsTable,
	}
	for {
		time.Sleep(period)
		for fileName, genFunc := range tableStats {
			table, err := genFunc(checkouts)
			if err == nil {
				saveTableAsCsv(table, filepath.Join(cfg.Workdir, fileName))
			}
		}
		for _, checkout := range checkouts {
			fileName := fmt.Sprintf("avg_%v.txt", checkout.Name)
			saveAvgBenchFile(checkout, filepath.Join(benchFolder, fileName))
		}
	}
}

func runInstance(info InstanceInfo) {
	logfile, err := os.Create(info.LogFile)
	if err != nil {
		tool.Failf("[%s] failed to create logfile: %s", info.Name, err)
	}
	cmd := osutil.GraciousCommand(info.ExecCommand, info.ExecCommandArgs...)
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	err = cmd.Start()
	if err != nil {
		tool.Failf("[%s] failed to start instance: %s", info.Name, err)
	}
	log.Printf("[%s] Instance started. Listening on %s", info.Name, info.HTTP)
	logfile.Close()
	err = cmd.Wait()
	tool.Failf("[%s] Instance exited: %s", info.Name, err)
}

func newCheckout(co TestbedCheckout, cfg *TestbedConfig, managerCfg *mgrconfig.Config) *CheckoutInfo {
	log.Printf("[%s] Checking out", co.Name)
	path := filepath.Join(cfg.Workdir, "checkouts", co.Name)
	if osutil.IsExist(path) {
		if !*flagCleanup {
			tool.Failf("path %s already exists", path)
		}
		osutil.RemoveAll(path)
	}
	repo := vcs.NewSyzkallerRepo(path)
	commit, err := repo.Poll(co.Repo, co.Branch)
	if err != nil {
		tool.Failf("failed to checkout %s (%s): %s", co.Repo, co.Branch, err)
	}
	log.Printf("[%s] Done. Latest commit: %s", co.Name, commit)
	log.Printf("[%s] Building", co.Name)
	if _, err := osutil.RunCmd(time.Hour, path, syz_instance.MakeBin); err != nil {
		tool.Failf("[%s] Make failed: %s", co.Name, err)
	}
	checkoutInfo := CheckoutInfo{
		Name: co.Name,
		Path: path,
	}
	for i := 1; i <= co.Count; i++ {
		name := fmt.Sprintf("%v-%d", co.Name, i)
		log.Printf("[%s] Generating workdir", name)
		workdir := filepath.Join(path, fmt.Sprintf("workdir_%d", i))
		err = osutil.MkdirAll(workdir)
		if err != nil {
			tool.Failf("failed to create dir %s", workdir)
		}
		if cfg.Corpus != "" {
			corpusPath := filepath.Join(workdir, "corpus.db")
			err = osutil.CopyFile(cfg.Corpus, corpusPath)
			if err != nil {
				tool.Failf("failed to copy corpus from %s: %s", cfg.Corpus, err)
			}
		}
		log.Printf("[%s] Generating syz-manager config", name)
		managerCfg.Name = name
		managerCfg.Workdir = workdir
		managerCfg.Syzkaller = path
		managerCfgPath := filepath.Join(path, fmt.Sprintf("syz_%d.cnf", i))
		err = config.SaveFile(managerCfgPath, managerCfg)
		if err != nil {
			tool.Failf("failed to save manager config to %s: %s", managerCfgPath, err)
		}
		bench := filepath.Join(path, fmt.Sprintf("bench_%d.txt", i))
		log := filepath.Join(path, fmt.Sprintf("log_%d.txt", i))
		checkoutInfo.Instances = append(checkoutInfo.Instances, InstanceInfo{
			Name:            managerCfg.Name,
			Workdir:         workdir,
			BenchFile:       bench,
			LogFile:         log,
			HTTP:            managerCfg.HTTP,
			ExecCommand:     filepath.Join(path, "bin", "syz-manager"),
			ExecCommandArgs: []string{"-config", managerCfgPath, "-bench", bench},
		})
		managerCfg.HTTP, err = increasePort(managerCfg.HTTP)
		if err != nil {
			tool.Failf("failed to inrease port number: %s", err)
		}
	}
	return &checkoutInfo
}

func increasePort(http string) (string, error) {
	host, portStr, err := net.SplitHostPort(http)
	if err != nil {
		return "", fmt.Errorf("invalid http value: %s", http)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port+1)), nil
}

func checkConfig(cfg *TestbedConfig) error {
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
	cfg.Corpus = osutil.Abs(cfg.Corpus)
	instanceNameRe := regexp.MustCompile(`^[0-9a-z\-]{1,20}$`)
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
		if co.Count < 0 {
			return fmt.Errorf("count cannot be negative")
		} else if co.Count == 0 {
			// The default value.
			co.Count = 1
		}
		if !instanceNameRe.MatchString(co.Name) {
			return fmt.Errorf("invalid instance name: %v", co.Name)
		}
		if names[co.Name] {
			return fmt.Errorf("duplicate instance name: %v", co.Name)
		}
		names[co.Name] = true
	}
	return nil
}
