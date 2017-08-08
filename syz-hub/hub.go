// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/log"
	. "github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/syz-hub/state"
)

var (
	flagConfig = flag.String("config", "", "config file")
)

type Config struct {
	Http    string
	Rpc     string
	Workdir string
	Clients []struct {
		Name string
		Key  string
	}
}

type Hub struct {
	mu   sync.Mutex
	st   *state.State
	keys map[string]string
}

func main() {
	flag.Parse()
	cfg := new(Config)
	if err := config.LoadFile(*flagConfig, cfg); err != nil {
		Fatal(err)
	}
	EnableLogCaching(1000, 1<<20)

	st, err := state.Make(cfg.Workdir)
	if err != nil {
		Fatalf("failed to load state: %v", err)
	}
	hub := &Hub{
		st:   st,
		keys: make(map[string]string),
	}
	for _, mgr := range cfg.Clients {
		hub.keys[mgr.Name] = mgr.Key
	}

	hub.initHttp(cfg.Http)

	s, err := NewRpcServer(cfg.Rpc, hub)
	if err != nil {
		Fatalf("failed to create rpc server: %v", err)
	}
	Logf(0, "serving rpc on tcp://%v", s.Addr())
	s.Serve()
}

func (hub *Hub) Connect(a *HubConnectArgs, r *int) error {
	name, err := hub.auth(a.Client, a.Key, a.Manager)
	if err != nil {
		return err
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()

	Logf(0, "connect from %v: fresh=%v calls=%v corpus=%v",
		name, a.Fresh, len(a.Calls), len(a.Corpus))
	if err := hub.st.Connect(name, a.Fresh, a.Calls, a.Corpus); err != nil {
		Logf(0, "connect error: %v", err)
		return err
	}
	return nil
}

func (hub *Hub) Sync(a *HubSyncArgs, r *HubSyncRes) error {
	name, err := hub.auth(a.Client, a.Key, a.Manager)
	if err != nil {
		return err
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()

	progs, more, err := hub.st.Sync(name, a.Add, a.Del)
	if err != nil {
		Logf(0, "sync error: %v", err)
		return err
	}
	r.Progs = progs
	r.More = more
	for _, repro := range a.Repros {
		if err := hub.st.AddRepro(name, repro); err != nil {
			Logf(0, "add repro error: %v", err)
		}
	}
	if a.NeedRepros {
		repro, err := hub.st.PendingRepro(name)
		if err != nil {
			Logf(0, "sync error: %v", err)
		}
		if repro != nil {
			r.Repros = [][]byte{repro}
		}
	}
	Logf(0, "sync from %v: recv: add=%v del=%v repros=%v; send: progs=%v repros=%v pending=%v",
		name, len(a.Add), len(a.Del), len(a.Repros), len(r.Progs), len(r.Repros), more)
	return nil
}

func (hub *Hub) auth(client, key, manager string) (string, error) {
	if key, ok := hub.keys[client]; !ok || key != key {
		Logf(0, "connect from unauthorized client %v", client)
		return "", fmt.Errorf("unauthorized manager")
	}
	if manager == "" {
		manager = client
	} else if !strings.HasPrefix(manager, client) {
		Logf(0, "manager %v does not have client prefix %v", manager, client)
		return "", fmt.Errorf("unauthorized manager")
	}
	return manager, nil
}
