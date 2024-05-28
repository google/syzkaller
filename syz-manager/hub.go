// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type keyGetter func() (string, error)

func pickGetter(key string) keyGetter {
	if key != "" {
		return func() (string, error) { return key, nil }
	}
	// Attempts oauth when the configured hub_key is empty.
	tokenCache, err := auth.MakeCache(http.NewRequest, http.DefaultClient.Do)
	if err != nil {
		log.Fatalf("failed to make auth cache %v", err)
	}
	return func() (string, error) {
		return tokenCache.Get(time.Now())
	}
}

func (mgr *Manager) hubSyncLoop(keyGet keyGetter) {
	hc := &HubConnector{
		mgr:           mgr,
		cfg:           mgr.cfg,
		target:        mgr.target,
		domain:        mgr.cfg.TargetOS + "/" + mgr.cfg.HubDomain,
		enabledCalls:  mgr.targetEnabledSyscalls,
		leak:          mgr.enabledFeatures&flatrpc.FeatureLeak != 0,
		fresh:         mgr.fresh,
		hubReproQueue: mgr.externalReproQueue,
		keyGet:        keyGet,

		statSendProgAdd:   stats.Create("hub send prog add", "", stats.Graph("hub progs")),
		statSendProgDel:   stats.Create("hub send prog del", "", stats.Graph("hub progs")),
		statRecvProg:      stats.Create("hub recv prog", "", stats.Graph("hub progs")),
		statRecvProgDrop:  stats.Create("hub recv prog drop", "", stats.NoGraph),
		statSendRepro:     stats.Create("hub send repro", "", stats.Graph("hub repros")),
		statRecvRepro:     stats.Create("hub recv repro", "", stats.Graph("hub repros")),
		statRecvReproDrop: stats.Create("hub recv repro drop", "", stats.NoGraph),
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
	domain         string
	enabledCalls   map[*prog.Syscall]bool
	leak           bool
	fresh          bool
	hubCorpus      map[hash.Sig]bool
	newRepros      [][]byte
	hubReproQueue  chan *Crash
	needMoreRepros chan chan bool
	keyGet         keyGetter

	statSendProgAdd   *stats.Val
	statSendProgDel   *stats.Val
	statRecvProg      *stats.Val
	statRecvProgDrop  *stats.Val
	statSendRepro     *stats.Val
	statRecvRepro     *stats.Val
	statRecvReproDrop *stats.Val
}

// HubManagerView restricts interface between HubConnector and Manager.
type HubManagerView interface {
	getMinimizedCorpus() (corpus, repros [][]byte)
	addNewCandidates(candidates []fuzzer.Candidate)
	hubIsUnreachable()
}

func (hc *HubConnector) loop() {
	var hub *rpctype.RPCClient
	var doneOnce bool
	for query := 0; ; time.Sleep(10 * time.Minute) {
		corpus, repros := hc.mgr.getMinimizedCorpus()
		hc.newRepros = append(hc.newRepros, repros...)
		if hub == nil {
			var err error
			if hub, err = hc.connect(corpus); err != nil {
				log.Logf(0, "failed to connect to hub at %v: %v", hc.cfg.HubAddr, err)
			} else {
				log.Logf(0, "connected to hub at %v, corpus %v", hc.cfg.HubAddr, len(corpus))
			}
		}
		if hub != nil {
			if err := hc.sync(hub, corpus); err != nil {
				log.Logf(0, "hub sync failed: %v", err)
				hub.Close()
				hub = nil
			} else {
				doneOnce = true
			}
		}
		query++
		const maxAttempts = 3
		if hub == nil && query >= maxAttempts && !doneOnce {
			hc.mgr.hubIsUnreachable()
		}
	}
}

func (hc *HubConnector) connect(corpus [][]byte) (*rpctype.RPCClient, error) {
	key, err := hc.keyGet()
	if err != nil {
		return nil, err
	}
	hub, err := rpctype.NewRPCClient(hc.cfg.HubAddr)
	if err != nil {
		return nil, err
	}
	a := &rpctype.HubConnectArgs{
		Client:  hc.cfg.HubClient,
		Key:     key,
		Manager: hc.cfg.Name,
		Domain:  hc.domain,
		Fresh:   hc.fresh,
	}
	for call := range hc.enabledCalls {
		a.Calls = append(a.Calls, call.Name)
	}
	hubCorpus := make(map[hash.Sig]bool)
	for _, inp := range corpus {
		hubCorpus[hash.Hash(inp)] = true
		a.Corpus = append(a.Corpus, inp)
	}
	// Never send more than this, this is never healthy but happens episodically
	// due to various reasons: problems with fallback coverage, bugs in kcov,
	// fuzzer exploiting our infrastructure, etc.
	const max = 100 * 1000
	if len(a.Corpus) > max {
		a.Corpus = a.Corpus[:max]
	}
	err = hub.Call("Hub.Connect", a, nil)
	// Hub.Connect request can be very large, so do it on a transient connection
	// (rpc connection buffers never shrink).
	hub.Close()
	if err != nil {
		return nil, err
	}
	hub, err = rpctype.NewRPCClient(hc.cfg.HubAddr)
	if err != nil {
		return nil, err
	}
	hc.hubCorpus = hubCorpus
	hc.fresh = false
	return hub, nil
}

func (hc *HubConnector) sync(hub *rpctype.RPCClient, corpus [][]byte) error {
	key, err := hc.keyGet()
	if err != nil {
		return err
	}
	a := &rpctype.HubSyncArgs{
		Client:  hc.cfg.HubClient,
		Key:     key,
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
		minimized, smashed, progDropped := hc.processProgs(r.Inputs)
		reproDropped := hc.processRepros(r.Repros)
		hc.statSendProgAdd.Add(len(a.Add))
		hc.statSendProgDel.Add(len(a.Del))
		hc.statSendRepro.Add(len(a.Repros))
		hc.statRecvProg.Add(len(r.Inputs) - progDropped)
		hc.statRecvProgDrop.Add(progDropped)
		hc.statRecvRepro.Add(len(r.Repros) - reproDropped)
		hc.statRecvReproDrop.Add(reproDropped)
		log.Logf(0, "hub sync: send: add %v, del %v, repros %v;"+
			" recv: progs %v (min %v, smash %v), repros %v; more %v",
			len(a.Add), len(a.Del), len(a.Repros),
			len(r.Inputs)-progDropped, minimized, smashed,
			len(r.Repros)-reproDropped, r.More)
		a.Add = nil
		a.Del = nil
		a.Repros = nil
		a.NeedRepros = false
		hc.newRepros = nil
		if len(r.Inputs)+r.More == 0 {
			return nil
		}
	}
}

func (hc *HubConnector) processProgs(inputs []rpctype.HubInput) (minimized, smashed, dropped int) {
	candidates := make([]fuzzer.Candidate, 0, len(inputs))
	for _, inp := range inputs {
		p, disabled, bad := parseProgram(hc.target, hc.enabledCalls, inp.Prog)
		if bad != nil || disabled {
			log.Logf(0, "rejecting program from hub (bad=%v, disabled=%v):\n%s",
				bad, disabled, inp)
			dropped++
			continue
		}
		min, smash := matchDomains(hc.domain, inp.Domain)
		var flags fuzzer.ProgFlags
		if min {
			minimized++
			flags |= fuzzer.ProgMinimized
		}
		if smash {
			smashed++
			flags |= fuzzer.ProgSmashed
		}
		candidates = append(candidates, fuzzer.Candidate{
			Prog:  p,
			Flags: flags,
		})
	}
	hc.mgr.addNewCandidates(candidates)
	return
}

func matchDomains(self, input string) (bool, bool) {
	if self == "" || input == "" {
		return true, true
	}
	min0, smash0 := splitDomains(self)
	min1, smash1 := splitDomains(input)
	min := min0 != min1
	smash := min || smash0 != smash1
	return min, smash
}

func splitDomains(domain string) (string, string) {
	delim0 := strings.IndexByte(domain, '/')
	if delim0 == -1 {
		return domain, ""
	}
	if delim0 == len(domain)-1 {
		return domain[:delim0], ""
	}
	delim1 := strings.IndexByte(domain[delim0+1:], '/')
	if delim1 == -1 {
		return domain, ""
	}
	return domain[:delim0+delim1+1], domain[delim0+delim1+2:]
}

func (hc *HubConnector) processRepros(repros [][]byte) int {
	dropped := 0
	for _, repro := range repros {
		_, disabled, bad := parseProgram(hc.target, hc.enabledCalls, repro)
		if bad != nil || disabled {
			log.Logf(0, "rejecting repro from hub (bad=%v, disabled=%v):\n%s",
				bad, disabled, repro)
			dropped++
			continue
		}
		// On a leak instance we override repro type to leak,
		// because otherwise repro package won't even enable leak detection
		// and we won't reproduce leaks from other instances.
		typ := crash.UnknownType
		if hc.leak {
			typ = crash.MemoryLeak
		}
		hc.hubReproQueue <- &Crash{
			fromHub: true,
			Report: &report.Report{
				Title:  "external repro",
				Type:   typ,
				Output: repro,
			},
		}
	}
	return dropped
}
