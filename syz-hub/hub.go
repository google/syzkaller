// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gcpsecret"
	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
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
	if gitRev != "" {
		log.Logf(0, "syz-hub revision %v", gitRev)
	}

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

	ln, err := net.Listen("tcp", cfg.RPC)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", cfg.RPC, err)
	}
	log.Logf(0, "serving api on http://%v", ln.Addr())
	apiSrv := &http.Server{
		Handler:           hub.apiHandler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		if err := apiSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to serve api: %v", err)
		}
	}()

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
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := apiSrv.Shutdown(shutdownCtx); err != nil {
		log.Logf(0, "api server shutdown error: %v", err)
	}
	// Keep hub.mu locked until process exit so background purge goroutines
	// cannot mutate on-disk state after the final Flush.
	hub.mu.Lock()
	hub.st.Flush()
}

func (hub *Hub) connect(name string, req *hubapi.ConnectReq) error {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	log.Logf(0, "connect from %v (%v): domain=%v fresh=%v calls=%v corpus=%v",
		name, req.HTTP, req.Domain, req.Fresh, len(req.Calls), len(req.Corpus))
	if err := hub.st.Connect(name, req.HTTP, req.Domain, req.Fresh, req.Calls, req.Corpus); err != nil {
		log.Logf(0, "connect error: %v", err)
		return err
	}
	return nil
}

func (hub *Hub) sync(name string, req *hubapi.SyncReq) (*hubapi.SyncResp, error) {
	hub.mu.Lock()
	defer hub.mu.Unlock()

	_, inputs, more, err := hub.st.Sync(name, nil, nil)
	if err != nil {
		log.Logf(0, "sync error: %v", err)
		return nil, err
	}
	resp := &hubapi.SyncResp{
		Inputs: inputs,
		More:   more,
	}
	for _, repro := range req.Repros {
		if err := hub.st.AddRepro(name, repro); err != nil {
			log.Logf(0, "add repro error: %v", err)
		}
	}
	if req.NeedRepros {
		repro, err := hub.st.PendingRepro(name)
		if err != nil {
			log.Logf(0, "sync error: %v", err)
		}
		if repro != nil {
			resp.Repros = [][]byte{repro}
		}
	}
	log.Logf(0, "sync from %v: recv: repros=%v; send: progs=%v repros=%v pending=%v",
		name, len(req.Repros), len(inputs), len(resp.Repros), more)
	return resp, nil
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

func (hub *Hub) verifyKey(token, expectedKey string) error {
	if strings.HasPrefix(expectedKey, auth.OauthMagic) {
		subj, err := hub.auth.DetermineAuthSubj(time.Now(), []string{"Bearer " + token})
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
	keyHash := sha256.Sum256([]byte(token))
	expectedHash := sha256.Sum256([]byte(expectedKey))
	if subtle.ConstantTimeCompare(keyHash[:], expectedHash[:]) != 1 {
		return fmt.Errorf("bad password")
	}
	// Success due to correct password.
	return nil
}

// Returns the verified manager identity or error.
func (hub *Hub) checkManager(client, token, manager string) (string, error) {
	expectedKey, ok := hub.keys[client]
	if !ok {
		log.Logf(0, "connect from unauthorized client %v", client)
		return "", fmt.Errorf("unauthorized manager")
	}
	if err := hub.verifyKey(token, expectedKey); err != nil {
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

// gitRev and gitRevLink are static for the lifetime of the binary.
var gitRev, gitRevLink = gitRevision()

func gitRevision() (rev, link string) {
	rev = prog.GitRevisionBase
	if !prog.GitRevisionKnown() {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					rev = s.Value
					break
				}
			}
		}
	}
	if len(rev) > 8 && rev != "unknown" {
		link = "https://github.com/google/syzkaller/commit/" + rev
		rev = rev[:8]
	}
	return rev, link
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
	keys := make(map[string]string, len(cfg.Clients))
	for _, mgr := range cfg.Clients {
		if !state.IsValidManagerName(mgr.Name) {
			return nil, nil, fmt.Errorf("invalid client name %q", mgr.Name)
		}
		if _, ok := keys[mgr.Name]; ok {
			return nil, nil, fmt.Errorf("duplicate client %v", mgr.Name)
		}
		key := strings.TrimSpace(mgr.Key)
		if key == "" {
			return nil, nil, fmt.Errorf("client %v: empty key", mgr.Name)
		}
		keys[mgr.Name] = key
	}
	return cfg, keys, nil
}
