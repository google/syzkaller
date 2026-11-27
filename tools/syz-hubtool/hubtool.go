// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-hubtool uploads local reproducers to syz-hub.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var (
		flagOS          = flag.String("os", runtime.GOOS, "target OS")
		flagArch        = flag.String("arch", runtime.GOARCH, "target Arch")
		flagHubAddress  = flag.String("addr", "", "hub address")
		flagHubClient   = flag.String("client", "", "hub API client")
		flagHubKey      = flag.String("key", "", "hub API key")
		flagHubManager  = flag.String("manager", "", "manager name to upload on behalf of")
		flagRepro       = flag.String("repro", "", "reproducer glob pattern to upload")
		flagCorpus      = flag.String("corpus", "", "coprpus file to upload")
		flagCorpusProgs = flag.String("corpus_progs", "", "a glob pattern of progs to add to corpus")
		flagWorkdir     = flag.String("workdir", "", "workdir to upload coprpus and reproducers")
		flagDrain       = flag.Bool("drain", false, "drain hub corpus and reproducers for the given manager")
	)
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatal(err)
	}
	if *flagWorkdir != "" {
		*flagRepro = filepath.Join(*flagWorkdir, "crashes", "*", "repro.prog")
		*flagCorpus = filepath.Join(*flagWorkdir, "corpus.db")
	}
	var repros, corpus [][]byte
	if *flagRepro != "" {
		repros = loadProgs(target, *flagRepro)
	}
	if *flagCorpus != "" {
		corpus = loadCorpus(target, *flagCorpus)
	} else if *flagCorpusProgs != "" {
		corpus = loadProgs(target, *flagCorpusProgs)
	}
	log.Printf("loaded %v reproducers, %v corpus programs", len(repros), len(corpus))
	if len(repros)+len(corpus) == 0 && !*flagDrain {
		return
	}
	log.Printf("connecting to hub at %v...", *flagHubAddress)
	client, err := hubapi.NewClient(*flagHubClient, *flagHubAddress, *flagHubKey)
	if err != nil {
		log.Fatalf("failed to connect to hub: %v", err)
	}
	if err := syncHub(context.Background(), client, *flagHubManager, corpus, repros, *flagDrain); err != nil {
		log.Fatal(err)
	}
}

func syncHub(ctx context.Context, client *hubapi.Client, manager string, corpus, repros [][]byte, drain bool) error {
	if len(repros)+len(corpus) == 0 && !drain {
		return nil
	}
	if err := client.Connect(ctx, &hubapi.ConnectReq{
		Manager: manager,
		Corpus:  corpus,
	}); err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	log.Printf("uploaded %v corpus programs", len(corpus))
	if len(repros) != 0 {
		if _, err := client.Sync(ctx, &hubapi.SyncReq{
			Manager: manager,
			Repros:  repros,
		}); err != nil {
			return fmt.Errorf("sync repros failed: %w", err)
		}
		log.Printf("uploaded %v reproducers", len(repros))
	}
	for drain {
		resp, err := client.Sync(ctx, &hubapi.SyncReq{
			Manager:    manager,
			NeedRepros: true,
		})
		if err != nil {
			return fmt.Errorf("drain sync failed: %w", err)
		}
		log.Printf("received %v progs, %v repros, %v more", len(resp.Inputs), len(resp.Repros), resp.More)
		if len(resp.Inputs)+len(resp.Repros) == 0 {
			break
		}
	}
	return nil
}

func loadProgs(target *prog.Target, reproGlob string) [][]byte {
	files, err := filepath.Glob(reproGlob)
	if err != nil {
		log.Fatal(err)
	}
	var repros [][]byte
	dedup := make(map[string]bool)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			log.Printf("failed to deserialize %v: %v", file, err)
			continue
		}
		if dedup[string(data)] {
			log.Printf("%v is a duplicate", file)
			continue
		}
		dedup[string(data)] = true
		repros = append(repros, data)
	}
	return repros
}

func loadCorpus(target *prog.Target, corpusDB string) [][]byte {
	progs, err := db.ReadCorpus(corpusDB, target)
	if err != nil {
		log.Fatal(err)
	}
	var corpus [][]byte
	for _, p := range progs {
		corpus = append(corpus, p.Serialize())
	}
	return corpus
}
