// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/rpctype"
)

var (
	flagWorkdir = flag.String("workdir", "", "dir with persistent artifacts")
	flagAddr    = flag.String("addr", "", "RPC listen address to connect managers")
	flagHTTP    = flag.String("http", "", "HTTP server listen address")
	flagV       = flag.Int("v", 0, "verbosity")
)

// Master manages persistent fuzzer state (input corpus and crashers).
type Master struct {
	mu        sync.Mutex
	managers  map[string]*Manager
	corpus    *PersistentSet
	crashers  *PersistentSet
	startTime time.Time
	lastInput time.Time
}

type Manager struct {
	name  string
	http  string
	input int
}

func main() {
	flag.Parse()
	if *flagWorkdir == "" {
		fatalf("-workdir is not set")
	}
	if *flagAddr == "" {
		fatalf("-addr is not set")
	}
	if *flagHTTP == "" {
		fatalf("-http is not set")
	}
	ln, err := net.Listen("tcp", *flagAddr)
	if err != nil {
		fatalf("failed to listen: %v", err)
	}

	m := &Master{}
	m.managers = make(map[string]*Manager)
	m.startTime = time.Now()
	m.lastInput = time.Now()
	logf(0, "loading corpus...")
	m.corpus = newPersistentSet(filepath.Join(*flagWorkdir, "corpus"), func(data []byte) bool {
		if _, err := prog.Deserialize(data); err != nil {
			logf(0, "deleting broken program: %v\n%s", err, data)
			return false
		}
		return true
	})
	m.crashers = newPersistentSet(filepath.Join(*flagWorkdir, "crashers"), nil)

	http.HandleFunc("/", m.httpInfo)
	http.HandleFunc("/minimize", m.httpMinimize)
	go func() {
		logf(0, "serving http on http://%v", *flagHTTP)
		panic(http.ListenAndServe(*flagHTTP, nil))
	}()

	logf(0, "serving rpc on tcp://%v", *flagAddr)
	s := rpc.NewServer()
	s.Register(m)
	go s.Accept(ln)

	m.loop()
}

func (m *Master) loop() {
	for range time.NewTicker(1 * time.Second).C {
	}
}

// Connect attaches new manager to master.
func (m *Master) Connect(a *MasterConnectArgs, r *MasterConnectRes) error {
	logf(1, "connect from %v (http://%v)", a.Name, a.Http)
	m.mu.Lock()
	defer m.mu.Unlock()

	mgr := &Manager{
		name: a.Name,
		http: a.Http,
	}
	m.managers[a.Name] = mgr
	r.Http = *flagHTTP
	return nil
}

// NewInput saves new interesting input on master.
func (m *Master) NewInput(a *NewMasterInputArgs, r *int) error {
	p, err := prog.Deserialize(a.Prog)
	if err != nil {
		logf(0, "bogus new input from %v: %v\n%s\n", a.Name, err, a.Prog)
		return fmt.Errorf("the program is bogus: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.corpus.add(a.Prog) {
		return nil
	}
	m.lastInput = time.Now()
	logf(1, "new input from %v: %s", a.Name, p)
	return nil
}

type NewCrasherArgs struct {
	Name        string
	Text        []byte
	Suppression []byte
	Prog        []byte
}

// NewCrasher saves new crasher input on master.
func (m *Master) NewCrasher(a *NewCrasherArgs, r *int) error {
	logf(0, "new crasher from %v", a.Name)
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.crashers.add(a.Text) {
		return nil // Already have this.
	}
	return nil
}

func (m *Master) PollInputs(a *MasterPollArgs, r *MasterPollRes) error {
	logf(2, "poll from %v", a.Name)
	m.mu.Lock()
	defer m.mu.Unlock()

	mgr := m.managers[a.Name]
	if mgr == nil {
		return fmt.Errorf("manager is not connected")
	}
	for i := 0; i < 100 && mgr.input < len(m.corpus.a); i++ {
		r.Inputs = append(r.Inputs, m.corpus.a[mgr.input])
		mgr.input++
	}
	return nil
}

func logf(v int, msg string, args ...interface{}) {
	if *flagV >= v {
		log.Printf(msg, args...)
	}
}

func fatalf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
