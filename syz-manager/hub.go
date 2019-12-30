// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

func (mgr *Manager) hubSyncLoop() {
	hc := &HubConnector{
		mgr:           mgr,
		cfg:           mgr.cfg,
		target:        mgr.target,
		stats:         mgr.stats,
		enabledCalls:  mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox],
		leak:          mgr.checkResult.Features[host.FeatureLeak].Enabled,
		fresh:         mgr.fresh,
		hubReproQueue: mgr.hubReproQueue,
	}
	if mgr.cfg.Reproduce && mgr.dash != nil {
		hc.needMoreRepros = mgr.needMoreRepros
	}
	hc.loop()
}

type HubConnector struct {
	mgr            HubManagerView
	cfg            *mgrconfig.Config
	target         *prog.Target
	stats          *Stats
	enabledCalls   []int
	leak           bool
	fresh          bool
	hubCorpus      map[hash.Sig]bool
	newRepros      [][]byte
	hubReproQueue  chan *Crash
	needMoreRepros chan chan bool
}

// HubManagerView restricts interface between HubConnector and Manager.
type HubManagerView interface {
	getMinimizedCorpus() (corpus, repros [][]byte)
	addNewCandidates(progs [][]byte)
}

func (hc *HubConnector) loop() {
	var hub *rpctype.RPCClient
	for ; ; time.Sleep(10 * time.Minute) {
		corpus, repros := hc.mgr.getMinimizedCorpus()
		hc.newRepros = append(hc.newRepros, repros...)
		if hub == nil {
			var err error
			if hub, err = hc.connect(corpus); err != nil {
				log.Logf(0, "failed to connect to hub at %v: %v", hc.cfg.HubAddr, err)
				continue
			}
			log.Logf(0, "connected to hub at %v, corpus %v", hc.cfg.HubAddr, len(corpus))
		}
		if err := hc.sync(hub, corpus); err != nil {
			log.Logf(0, "hub sync failed: %v", err)
			hub.Close()
			hub = nil
		}
	}
}

func (hc *HubConnector) connect(corpus [][]byte) (*rpctype.RPCClient, error) {
	a := &rpctype.HubConnectArgs{
		Client:  hc.cfg.HubClient,
		Key:     hc.cfg.HubKey,
		Manager: hc.cfg.Name,
		Fresh:   hc.fresh,
	}
	for _, id := range hc.enabledCalls {
		a.Calls = append(a.Calls, hc.target.Syscalls[id].Name)
	}
	hubCorpus := make(map[hash.Sig]bool)
	for _, inp := range corpus {
		hubCorpus[hash.Hash(inp)] = true
		a.Corpus = append(a.Corpus, inp)
	}
	// Hub.Connect request can be very large, so do it on a transient connection
	// (rpc connection buffers never shrink).
	if err := rpctype.RPCCall(hc.cfg.HubAddr, "Hub.Connect", a, nil); err != nil {
		return nil, err
	}
	hub, err := rpctype.NewRPCClient(hc.cfg.HubAddr)
	if err != nil {
		return nil, err
	}
	hc.hubCorpus = hubCorpus
	hc.fresh = false
	return hub, nil
}

func (hc *HubConnector) sync(hub *rpctype.RPCClient, corpus [][]byte) error {
	a := &rpctype.HubSyncArgs{
		Client:  hc.cfg.HubClient,
		Key:     hc.cfg.HubKey,
		Manager: hc.cfg.Name,
	}
	sigs := make(map[hash.Sig]bool)
	for _, inp := range corpus {
		sig := hash.Hash(inp)
		sigs[sig] = true
		if hc.hubCorpus[sig] {
			continue
		}
		hc.hubCorpus[sig] = true
		a.Add = append(a.Add, inp)
	}
	for sig := range hc.hubCorpus {
		if sigs[sig] {
			continue
		}
		delete(hc.hubCorpus, sig)
		a.Del = append(a.Del, sig.String())
	}
	if hc.needMoreRepros != nil {
		needReproReply := make(chan bool)
		hc.needMoreRepros <- needReproReply
		a.NeedRepros = <-needReproReply
	}
	a.Repros = hc.newRepros
	for {
		r := new(rpctype.HubSyncRes)
		if err := hub.Call("Hub.Sync", a, r); err != nil {
			return err
		}
		progDropped := hc.processProgs(r.Progs)
		reproDropped := hc.processRepros(r.Repros)
		hc.stats.hubSendProgAdd.add(len(a.Add))
		hc.stats.hubSendProgDel.add(len(a.Del))
		hc.stats.hubSendRepro.add(len(a.Repros))
		hc.stats.hubRecvProg.add(len(r.Progs) - progDropped)
		hc.stats.hubRecvProgDrop.add(progDropped)
		hc.stats.hubRecvRepro.add(len(r.Repros) - reproDropped)
		hc.stats.hubRecvReproDrop.add(reproDropped)
		log.Logf(0, "hub sync: send: add %v, del %v, repros %v;"+
			" recv: progs %v, repros %v; more %v",
			len(a.Add), len(a.Del), len(a.Repros),
			len(r.Progs)-progDropped, len(r.Repros)-reproDropped, r.More)
		a.Add = nil
		a.Del = nil
		a.Repros = nil
		a.NeedRepros = false
		hc.newRepros = nil
		if len(r.Progs)+r.More == 0 {
			return nil
		}
	}
}

func (hc *HubConnector) processProgs(progs [][]byte) int {
	dropped := 0
	candidates := make([][]byte, 0, len(progs))
	for _, inp := range progs {
		if _, err := hc.target.Deserialize(inp, prog.NonStrict); err != nil {
			dropped++
			continue
		}
		candidates = append(candidates, inp)
	}
	hc.mgr.addNewCandidates(candidates)
	return dropped
}

func (hc *HubConnector) processRepros(repros [][]byte) int {
	dropped := 0
	for _, repro := range repros {
		if _, err := hc.target.Deserialize(repro, prog.NonStrict); err != nil {
			dropped++
			continue
		}
		// On a leak instance we override repro type to leak,
		// because otherwise repro package won't even enable leak detection
		// and we won't reproduce leaks from other instances.
		typ := report.Unknown
		if hc.leak {
			typ = report.MemoryLeak
		}
		hc.hubReproQueue <- &Crash{
			vmIndex: -1,
			hub:     true,
			Report: &report.Report{
				Title:  "external repro",
				Type:   typ,
				Output: repro,
			},
		}
	}
	return dropped
}
