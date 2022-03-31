// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cuttlefish allows to use Cuttlefish Android emulators hosted on Google Compute Engine
// (GCE) virtual machines as VMs. It is assumed that syz-manager also runs on GCE as VMs are
// created in the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, how to build GCE-compatible images:
// https://cloud.google.com/compute/docs/tutorials/building-images
package cuttlefish

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"

	gcevm "github.com/google/syzkaller/vm/gce"
)

func init() {
	vmimpl.Register("cuttlefish", ctor, true)
}

type Config struct {
	Count       int    `json:"count"`        // number of VMs to use
	MachineType string `json:"machine_type"` // GCE machine type (e.g. "n1-standard-4")
	GCEImage    string `json:"gce_image"`    // pre-created GCE image to use
	Preemptible bool   `json:"preemptible"`  // use preemptible VMs if available (defaults to true)
}

type Pool struct {
	cfg     *Config
	env     *vmimpl.Env
	gcePool *gcevm.Pool
}

type instance struct {
	debug   bool
	gceInst vmimpl.Instance
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	log.Logf(0, "cuttlefish.ctor()")
	if env.Name == "" {
		return nil, fmt.Errorf("config param name is empty (required for GCE)")
	}
	cfg := &Config{
		Count:       1,
		Preemptible: true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse gce vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 1000 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}
	if cfg.MachineType == "" {
		return nil, fmt.Errorf("machine_type parameter is empty")
	}
	if cfg.GCEImage == "" {
		return nil, fmt.Errorf("gce_image parameter is empty")
	}

	ctx, err := gce.NewContext()
	if err != nil {
		return nil, fmt.Errorf("failed to init gce: %v", err)
	}
	log.Logf(0, "GCE initialized: running on %v, internal IP %v, project %v, zone %v, net %v/%v",
		ctx.Instance, ctx.InternalIP, ctx.ProjectID, ctx.ZoneID, ctx.Network, ctx.Subnetwork)

	pool := &Pool{
		cfg: cfg,
		env: env,
		// This nested gcevm.Pool object will let us re-use the existing Create() function.
		gcePool: &gcevm.Pool{
			Env: env,
			Cfg: &gcevm.Config{
				Count:       cfg.Count,
				MachineType: cfg.MachineType,
				GCEImage:    cfg.GCEImage,
				Preemptible: cfg.Preemptible,
			},
			GCE: ctx,
		},
	}

	return pool, nil
}

func (pool *Pool) Count() int {
	log.Logf(0, "cuttlefish.pool.Count()")
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	log.Logf(0, "cuttlefish.pool.Create(%s, %d)", workdir, index)
	gceInst, err := pool.gcePool.Create(workdir, index)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying gce instance: %s", err)
	}

	inst := &instance{
		debug:   pool.env.Debug,
		gceInst: gceInst,
	}

	// Start a Cuttlefish device on the GCE instance
	// TODO: pass it the specific kernel artifact using -kernel_path and -initramfs_path flags
	if err := inst.runOnHost(10*time.Minute, "./bin/launch_cvd -daemon"); err != nil {
		return nil, fmt.Errorf("failed to start cuttlefish: %s", err)
	}

	if err := inst.runOnHost(10*time.Minute, "adb wait-for-device"); err != nil {
		return nil, fmt.Errorf("failed while waiting for device: %s", err)
	}

	if err := inst.runOnHost(5*time.Minute, "adb root"); err != nil {
		return nil, fmt.Errorf("failed to get root access to device: %s", err)
	}

	return inst, nil
}

func (inst *instance) runOnHost(timeout time.Duration, cmd string) error {
	outc, errc, err := inst.gceInst.Run(timeout, nil, cmd)
	if err != nil {
		return fmt.Errorf("failed to run command: %s", err)
	}

	for {
		select {
		case <-vmimpl.Shutdown:
			return nil
		case err := <-errc:
			if err != nil {
				return fmt.Errorf("error while running: %s", err)
			}
			return nil
		case out, ok := <-outc:
			if ok && inst.debug {
				log.Logf(0, string(out))
			}
		}
	}
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	log.Logf(0, "cuttlefish.instance.Copy(%s)", hostSrc)
	return "", fmt.Errorf("not implemented")
}

func (inst *instance) Forward(port int) (string, error) {
	log.Logf(0, "cuttlefish.instance.Forward(%d)", port)
	return "", fmt.Errorf("not implemented")
}

func (inst *instance) Close() {
	// Stop Cuttlefish before shutting down the GCE instance.
	inst.runOnHost(10*time.Minute, "./bin/stop_cvd")
	inst.gceInst.Close()
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	log.Logf(0, "cuttlefish.instance.Run(%s)", command)
	return nil, nil, fmt.Errorf("not implemented")
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	log.Logf(0, "cuttlefish.instance.Diagnose()")
	return nil, false
}
