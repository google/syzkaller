// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gcpsecret"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/tool"
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
	defer tool.Init()()
	log.EnableLogCaching(1000, 1<<20)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, keys, err := loadConfig(ctx, *flagConfig)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	st, err := state.Make(cfg.Workdir)
	if err != nil {
		log.Fatalf("failed to load state: %v", err)
	}
	hub := &Hub{
		st:   st,
		keys: keys,
		auth: auth.MakeEndpoint(auth.GoogleTokenInfoEndpoint),
	}

	s, err := rpctype.NewRPCServer(cfg.RPC, "Hub", hub)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	go s.Serve()

	http.HandleFunc("/", hub.httpSummary)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	tool.ServeHTTP(cfg.HTTP)
	go hub.purgeOldManagers()

	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	<-shutdown
	log.Logf(0, "shutting down...")
	// Keep hub.mu locked until process exit so background RPC or purge goroutines
	// cannot mutate on-disk state after the final Flush.
	hub.mu.Lock()
	hub.st.Flush()
}

func (hub *Hub) Connect(a *rpctype.HubConnectArgs, r *int) error {
	name, err := hub.checkManager(a.Client, a.Key, a.Manager)
	if err != nil {
		return err
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()

	log.Logf(0, "connect from %v (%v): domain=%v fresh=%v calls=%v corpus=%v",
		name, a.HTTP, a.Domain, a.Fresh, len(a.Calls), len(a.Corpus))
	if err := hub.st.Connect(name, a.HTTP, a.Domain, a.Fresh, a.Calls, a.Corpus); err != nil {
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
		r.Progs = make([][]byte, 0, len(inputs))
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

func (hub *Hub) purgeOldManagers() {
	for range time.NewTicker(time.Hour).C {
		hub.mu.Lock()
		if err := hub.st.PurgeOldManagers(); err != nil {
			log.Logf(0, "failed to purge managers: %v", err)
		}
		hub.mu.Unlock()
	}
}

func (hub *Hub) verifyKey(key, expectedKey string) error {
	if strings.HasPrefix(expectedKey, auth.OauthMagic) {
		subj, err := hub.auth.DetermineAuthSubj(time.Now(), []string{key})
		if err != nil {
			return err
		}
		subjHash := sha256.Sum256([]byte(subj))
		expectedHash := sha256.Sum256([]byte(expectedKey))
		if subtle.ConstantTimeCompare(subjHash[:], expectedHash[:]) != 1 {
			return fmt.Errorf("bad token")
		}
		// Success due to correct token.
		return nil
	}
	keyHash := sha256.Sum256([]byte(key))
	expectedHash := sha256.Sum256([]byte(expectedKey))
	if subtle.ConstantTimeCompare(keyHash[:], expectedHash[:]) != 1 {
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
	if !state.IsValidManagerName(manager) {
		log.Logf(0, "manager %v has bad name", manager)
		return "", fmt.Errorf("unauthorized manager")
	}
	return manager, nil
}

func loadConfig(ctx context.Context, filename string) (*Config, map[string]string, error) {
	cfg := new(Config)
	if strings.HasPrefix(filename, "gcp-secret:") || strings.HasPrefix(filename, "env:") {
		data, err := gcpsecret.Resolve(ctx, filename)
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(data) == "" {
			return nil, nil, fmt.Errorf("config %v is empty", filename)
		}
		if err := config.LoadData([]byte(data), cfg); err != nil {
			return nil, nil, err
		}
	} else if err := config.LoadFile(filename, cfg); err != nil {
		return nil, nil, err
	}
	keys, err := resolveClientKeys(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, keys, nil
}

func resolveClientKeys(ctx context.Context, cfg *Config) (map[string]string, error) {
	keys := make(map[string]string, len(cfg.Clients))
	for _, mgr := range cfg.Clients {
		if !state.IsValidManagerName(mgr.Name) {
			return nil, fmt.Errorf("invalid client name %q", mgr.Name)
		}
		if _, ok := keys[mgr.Name]; ok {
			return nil, fmt.Errorf("duplicate client %v", mgr.Name)
		}
		key, err := gcpsecret.Resolve(ctx, mgr.Key)
		if err != nil {
			return nil, fmt.Errorf("client %v: %w", mgr.Name, err)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("client %v: empty key", mgr.Name)
		}
		keys[mgr.Name] = key
	}
	return keys, nil
}
