// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/stat"
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

		statRecvProg:      stat.New("hub recv prog", "", stat.Graph("hub progs")),
		statRecvProgDrop:  stat.New("hub recv prog drop", "", stat.NoGraph),
		statSendRepro:     stat.New("hub send repro", "", stat.Graph("hub repros")),
		statRecvRepro:     stat.New("hub recv repro", "", stat.Graph("hub repros")),
		statRecvReproDrop: stat.New("hub recv repro drop", "", stat.NoGraph),
	}
	if mgr.cfg.Reproduce && mgr.dash != nil {
		// Request reproducers from hub only if there is nothing else to reproduce.
		hc.needMoreRepros = mgr.reproLoop.Empty
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
	newRepros      [][]byte
	hubReproQueue  chan *manager.Crash
	needMoreRepros func() bool
	keyGet         keyGetter

	statRecvProg      *stat.Val
	statRecvProgDrop  *stat.Val
	statSendRepro     *stat.Val
	statRecvRepro     *stat.Val
	statRecvReproDrop *stat.Val
}

// HubManagerView restricts interface between HubConnector and Manager.
type HubManagerView interface {
	getMinimizedCorpus() []*corpus.Item
	getNewRepros() [][]byte
	addNewCandidates(candidates []fuzzer.Candidate)
	needMoreCandidates() bool
	hubIsUnreachable()
}

func (hc *HubConnector) loop() {
	var hub *rpctype.RPCClient
	var doneOnce bool
	var connectTime time.Time
	for query := 0; ; time.Sleep(10 * time.Minute) {
		if hub == nil {
			var corpus []*corpus.Item
			// If we are using fake coverage, don't send our corpus to the hub.
			// It should be lower quality than coverage-guided corpus.
			// However still send repros and accept new inputs.
			if hc.cfg.Cover {
				corpus = hc.mgr.getMinimizedCorpus()
			}
			var err error
			if hub, err = hc.connect(corpus); err != nil {
				log.Logf(0, "failed to connect to hub at %v: %v", hc.cfg.HubAddr, err)
			} else {
				log.Logf(0, "connected to hub at %v, corpus %v", hc.cfg.HubAddr, len(corpus))
				connectTime = time.Now()
			}
		}
		if hub != nil && hc.mgr.needMoreCandidates() {
			repros := hc.mgr.getNewRepros()
			hc.newRepros = append(hc.newRepros, repros...)
			if err := hc.sync(hub); err != nil {
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
		// We used to send corpus updates (added/removed elements) to the hub in each sync.
		// But that produced too much churn since hub algorithm is O(N^2) (distributing everything
		// to everybody), and lots of new inputs are later removed (either we can't reproduce coverage
		// after restart, or inputs removed during corpus minimization). So now we don't send new inputs
		// in each sync, instead we aim at sending corpus once after initial triage. This solves
		// the problem with non-reproducible/removed inputs. Typical instance life-time on syzbot is <24h,
		// for such instances we send the corpus once. If an instance somehow lives for longer, then we
		// re-connect and re-send once in a while (e.g. a local long-running instance).
		if hub != nil && time.Since(connectTime) > 30*time.Hour {
			log.Logf(0, "re-syncing with hub")
			hub.Close()
			hub = nil
		}
	}
}

func (hc *HubConnector) connect(corpus []*corpus.Item) (*rpctype.RPCClient, error) {
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
	for _, inp := range corpus {
		a.Corpus = append(a.Corpus, inp.Prog.Serialize())
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
	hc.fresh = false
	return hub, nil
}

func (hc *HubConnector) sync(hub *rpctype.RPCClient) error {
	key, err := hc.keyGet()
	if err != nil {
		return err
	}
	a := &rpctype.HubSyncArgs{
		Client:  hc.cfg.HubClient,
		Key:     key,
		Manager: hc.cfg.Name,
	}
	if hc.needMoreRepros != nil {
		a.NeedRepros = hc.needMoreRepros()
	}
	a.Repros = hc.newRepros
	for {
		r := new(rpctype.HubSyncRes)
		if err := hub.Call("Hub.Sync", a, r); err != nil {
			return err
		}
		minimized, smashed, progDropped := hc.processProgs(r.Inputs)
		reproDropped := hc.processRepros(r.Repros)
		hc.statSendRepro.Add(len(a.Repros))
		hc.statRecvProg.Add(len(r.Inputs) - progDropped)
		hc.statRecvProgDrop.Add(progDropped)
		hc.statRecvRepro.Add(len(r.Repros) - reproDropped)
		hc.statRecvReproDrop.Add(reproDropped)
		log.Logf(0, "hub sync: repros %v;"+
			" recv: progs %v (min %v, smash %v), repros %v; more %v",
			len(a.Repros), len(r.Inputs)-progDropped, minimized, smashed,
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
		p, err := hc.parseProgram(inp.Prog)
		if err != nil {
			log.Logf(0, "rejecting program from hub: %v\n%s", err, inp.Prog)
			dropped++
			continue
		}
		min, smash := matchDomains(hc.domain, inp.Domain)
		var flags fuzzer.ProgFlags
		if min && len(p.Calls) < manager.ReminimizeThreshold {
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
		_, err := hc.parseProgram(repro)
		if err != nil {
			log.Logf(0, "rejecting repro from hub: %v\n%s", err, repro)
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
		hc.hubReproQueue <- &manager.Crash{
			FromHub: true,
			Report: &report.Report{
				Type:   typ,
				Output: repro,
			},
		}
	}
	return dropped
}

func (hc *HubConnector) parseProgram(data []byte) (*prog.Prog, error) {
	p, err := manager.LoadProg(hc.target, data)
	if err != nil {
		return nil, err
	}
	if !p.OnlyContains(hc.enabledCalls) {
		return nil, fmt.Errorf("contains disabled calls")
	}
	return p, nil
}
