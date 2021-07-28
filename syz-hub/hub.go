// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/syz-hub/state"
)

var (
	flagConfig = flag.String("config", "", "config file")
)

type Config struct {
	HTTP    string
	RPC     string
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
	auth auth.Endpoint
}

func main() {
	flag.Parse()
	cfg := new(Config)
	if err := config.LoadFile(*flagConfig, cfg); err != nil {
		log.Fatal(err)
	}
	log.EnableLogCaching(1000, 1<<20)

	st, err := state.Make(cfg.Workdir)
	if err != nil {
		log.Fatalf("failed to load state: %v", err)
	}
	hub := &Hub{
		st:   st,
		keys: make(map[string]string),
		auth: auth.MakeEndpoint(auth.GoogleTokenInfoEndpoint),
	}
	for _, mgr := range cfg.Clients {
		hub.keys[mgr.Name] = mgr.Key
	}

	hub.initHTTP(cfg.HTTP)

	s, err := rpctype.NewRPCServer(cfg.RPC, "Hub", hub)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	s.Serve()
}

func (hub *Hub) Connect(a *rpctype.HubConnectArgs, r *int) error {
	name, err := hub.checkManager(a.Client, a.Key, a.Manager)
	if err != nil {
		return err
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()

	log.Logf(0, "connect from %v: domain=%v fresh=%v calls=%v corpus=%v",
		name, a.Domain, a.Fresh, len(a.Calls), len(a.Corpus))
	if err := hub.st.Connect(name, a.Domain, a.Fresh, a.Calls, a.Corpus); err != nil {
		log.Logf(0, "connect error: %v", err)
		return err
	}
	return nil
}

func (hub *Hub) Sync(a *rpctype.HubSyncArgs, r *rpctype.HubSyncRes) error {
	name, err := hub.checkManager(a.Client, a.Key, a.Manager)
	if err != nil {
		return err
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()

	domain, inputs, more, err := hub.st.Sync(name, a.Add, a.Del)
	if err != nil {
		log.Logf(0, "sync error: %v", err)
		return err
	}
	if domain != "" {
		r.Inputs = inputs
	} else {
		for _, inp := range inputs {
			r.Progs = append(r.Progs, inp.Prog)
		}
	}
	r.More = more
	for _, repro := range a.Repros {
		if err := hub.st.AddRepro(name, repro); err != nil {
			log.Logf(0, "add repro error: %v", err)
		}
	}
	if a.NeedRepros {
		repro, err := hub.st.PendingRepro(name)
		if err != nil {
			log.Logf(0, "sync error: %v", err)
		}
		if repro != nil {
			r.Repros = [][]byte{repro}
		}
	}
	log.Logf(0, "sync from %v: recv: add=%v del=%v repros=%v; send: progs=%v repros=%v pending=%v",
		name, len(a.Add), len(a.Del), len(a.Repros), len(inputs), len(r.Repros), more)
	return nil
}

func (hub *Hub) verifyKey(key, expectedKey string) error {
	if strings.HasPrefix(expectedKey, auth.OauthMagic) {
		subj, err := hub.auth.DetermineAuthSubj(time.Now(), []string{key})
		if err != nil {
			return err
		}
		if subj != expectedKey {
			return fmt.Errorf("bad token")
		}
		// Success due to correct token.
		return nil
	}
	if key != expectedKey {
		return fmt.Errorf("bad password")
	}
	// Success due to correct password.
	return nil
}

// Returns the verified manager identity or error.
func (hub *Hub) checkManager(client, key, manager string) (string, error) {
	expectedKey, ok := hub.keys[client]
	if !ok {
		log.Logf(0, "connect from unauthorized client %v", client)
		return "", fmt.Errorf("unauthorized manager")
	}
	if err := hub.verifyKey(key, expectedKey); err != nil {
		log.Logf(0, "connect from unauthorized client %v", client)
		return "", fmt.Errorf("unauthorized manager")
	}
	if manager == "" {
		manager = client
	} else if !strings.HasPrefix(manager, client) {
		log.Logf(0, "manager %v does not have client prefix %v", manager, client)
		return "", fmt.Errorf("unauthorized manager")
	}
	return manager, nil
}
