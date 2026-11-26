// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

func (mgr *Manager) hubSyncLoop(ctx context.Context, enabledSyscalls map[*prog.Syscall]bool) {
	client, err := hubapi.NewClient(mgr.cfg.HubClient, mgr.cfg.HubAddr, mgr.cfg.HubKey)
	if err != nil {
		log.Fatalf("failed to create hubapi connection: %v", err)
	}
	hc := &HubConnector{
		mgr:           mgr,
		cfg:           mgr.cfg,
		webAddr:       publicWebAddr(mgr.cfg),
		target:        mgr.target,
		domain:        mgr.cfg.TargetOS + "/" + mgr.cfg.HubDomain,
		enabledCalls:  enabledSyscalls,
		leak:          mgr.enabledFeatures&flatrpc.FeatureLeak != 0,
		fresh:         mgr.fresh,
		hubReproQueue: mgr.externalReproQueue,
		client:        client,

		statRecvProg:      stat.New("hub recv prog", "", stat.Graph("hub progs")),
		statRecvProgDrop:  stat.New("hub recv prog drop", "", stat.NoGraph),
		statSendRepro:     stat.New("hub send repro", "", stat.Graph("hub repros")),
		statRecvRepro:     stat.New("hub recv repro", "", stat.Graph("hub repros")),
		statRecvReproDrop: stat.New("hub recv repro drop", "", stat.NoGraph),
	}
	if mgr.cfg.Reproduce && mgr.dash != nil && mgr.cfg.ReproduceOnlyRe == nil {
		// Request reproducers from hub only if there is nothing else to reproduce.
		// Hub repros carry no title, so with reproduce_only set they'd always be
		// filtered out — don't request them.
		hc.needMoreRepros = mgr.reproLoop.Empty
	}
	hc.loop(ctx)
}

type HubConnector struct {
	mgr            HubManagerView
	cfg            *mgrconfig.Config
	webAddr        string
	target         *prog.Target
	domain         string
	enabledCalls   map[*prog.Syscall]bool
	leak           bool
	fresh          bool
	newRepros      [][]byte
	hubReproQueue  chan *manager.Crash
	needMoreRepros func() bool
	client         *hubapi.Client

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

func (hc *HubConnector) loop(ctx context.Context) {
	var connected bool
	var doneOnce bool
	var connectTime time.Time
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for query := 0; ; {
		if !connected {
			var corpus []*corpus.Item
			// If we are using fake coverage, don't send our corpus to the hub.
			// It should be lower quality than coverage-guided corpus.
			// However still send repros and accept new inputs.
			if hc.cfg.Cover {
				corpus = hc.mgr.getMinimizedCorpus()
			}
			if err := hc.connect(ctx, corpus); err != nil {
				log.Logf(0, "failed to connect to hub at %v: %v", hc.cfg.HubAddr, err)
			} else {
				connected = true
				log.Logf(0, "connected to hub at %v, corpus %v", hc.cfg.HubAddr, len(corpus))
				connectTime = time.Now()
			}
		}
		if connected && hc.mgr.needMoreCandidates() {
			repros := hc.mgr.getNewRepros()
			hc.newRepros = append(hc.newRepros, repros...)
			if err := hc.sync(ctx); err != nil {
				log.Logf(0, "hub sync failed: %v", err)
				connected = false
			} else {
				doneOnce = true
			}
		}
		query++
		const maxAttempts = 3
		if !connected && query >= maxAttempts && !doneOnce {
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
		if connected && time.Since(connectTime) > 30*time.Hour {
			log.Logf(0, "re-syncing with hub")
			connected = false
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (hc *HubConnector) connect(ctx context.Context, corpus []*corpus.Item) error {
	req := &hubapi.ConnectReq{
		Manager: hc.cfg.Name,
		HTTP:    hc.webAddr,
		Domain:  hc.domain,
		Fresh:   hc.fresh,
	}
	for call := range hc.enabledCalls {
		req.Calls = append(req.Calls, call.Name)
	}
	for _, inp := range corpus {
		req.Corpus = append(req.Corpus, inp.Prog.Serialize())
	}
	// Never send more than this, this is never healthy but happens episodically
	// due to various reasons: problems with fallback coverage, bugs in kcov,
	// fuzzer exploiting our infrastructure, etc.
	const max = 100 * 1000
	if len(req.Corpus) > max {
		req.Corpus = req.Corpus[:max]
	}
	if err := hc.client.Connect(ctx, req); err != nil {
		return err
	}
	hc.fresh = false
	return nil
}

func (hc *HubConnector) sync(ctx context.Context) error {
	req := &hubapi.SyncReq{
		Manager: hc.cfg.Name,
	}
	if hc.needMoreRepros != nil {
		req.NeedRepros = hc.needMoreRepros()
	}
	req.Repros = hc.newRepros
	for {
		resp, err := hc.client.Sync(ctx, req)
		if err != nil {
			return err
		}
		minimized, smashed, progDropped := hc.processProgs(resp.Inputs)
		reproDropped := hc.processRepros(resp.Repros)
		hc.statSendRepro.Add(len(req.Repros))
		hc.statRecvProg.Add(len(resp.Inputs) - progDropped)
		hc.statRecvProgDrop.Add(progDropped)
		hc.statRecvRepro.Add(len(resp.Repros) - reproDropped)
		hc.statRecvReproDrop.Add(reproDropped)
		log.Logf(0, "hub sync: repros %v;"+
			" recv: progs %v (min %v, smash %v), repros %v; more %v",
			len(req.Repros), len(resp.Inputs)-progDropped, minimized, smashed,
			len(resp.Repros)-reproDropped, resp.More)
		req.Repros = nil
		req.NeedRepros = false
		hc.newRepros = nil
		if len(resp.Inputs)+resp.More == 0 {
			return nil
		}
	}
}

func (hc *HubConnector) processProgs(inputs []hubapi.Input) (minimized, smashed, dropped int) {
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
	p, err := manager.ParseSeed(hc.target, data)
	if err != nil {
		return nil, err
	}
	if !p.OnlyContains(hc.enabledCalls) {
		return nil, fmt.Errorf("contains disabled calls")
	}
	return p, nil
}
