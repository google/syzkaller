// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// sudo apt-get install golang-go clang-format

package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/net/context"
	"google.golang.org/api/compute/v0.beta"
)

var (
	flagConfig = flag.String("config", "", "config file")

	cfg           *Config
	ctx           context.Context
	storageClient *storage.Client
	computeService *compute.Service
)

type Config struct {
	Image_Archive string
	Image_Path    string
	Http_Port     int
	Machine_Type  string
	Machine_Count int
	Sandbox       string
	Procs         int
}

func main() {
	flag.Parse()
	cfg = readConfig(*flagConfig)

	var err error
	ctx = context.Background()
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		fatalf("failed to create cloud storage client: %v", err)
	}

	tokenSource, err := google.DefaultTokenSource(ctx, compute.CloudPlatformScope)
	if err != nil {
		fatalf("failed to get a token source: %v", err)
	}
	httpClient := oauth2.NewClient(ctx, tokenSource)
	computeService, _ = compute.New(httpClient)

	archive, updated, err := openFile(cfg.Image_Archive)
	if err != nil {
		fatalf("%v", err)
	}
	log.Printf("archive updated: %v", updated)

	if false {
		if err := os.RemoveAll("image"); err != nil {
			fatalf("failed to remove image dir: %v", err)
		}
		if err := downloadAndExtract(archive, "image"); err != nil {
			fatalf("failed to download and extract %v: %v", cfg.Image_Archive, err)
		}

	if err := uploadFile("image/disk.tar.gz", cfg.Image_Path); err != nil {
		fatalf("failed to upload image: %v", err)
	}
	}


		

	if false {
		syzBin, err := updateSyzkallerBuild()
		if err != nil {
			fatalf("failed to update/build syzkaller: %v", err)
		}
		_ = syzBin
	}
}

func readConfig(filename string) *Config {
	if filename == "" {
		fatalf("supply config in -config flag")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fatalf("failed to read config file: %v", err)
	}
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		fatalf("failed to parse config file: %v", err)
	}
	return cfg
}

func openFile(file string) (*storage.ObjectHandle, time.Time, error) {
	pos := strings.IndexByte(file, '/')
	if pos == -1 {
		return nil, time.Time{}, fmt.Errorf("invalid GCS file name: %v", file)
	}
	bkt := storageClient.Bucket(file[:pos])
	f := bkt.Object(file[pos+1:])
	attrs, err := f.Attrs(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to read %v attributes: %v", file, err)
	}
	if !attrs.Deleted.IsZero() {
		return nil, time.Time{}, fmt.Errorf("file %v is deleted", file)
	}
	f = f.WithConditions(
		storage.IfGenerationMatch(attrs.Generation),
		storage.IfMetaGenerationMatch(attrs.MetaGeneration),
	)
	return f, attrs.Updated, nil
}

func downloadAndExtract(f *storage.ObjectHandle, dir string) error {
	r, err := f.NewReader(ctx)
	if err != nil {
		return err
	}
	defer r.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	ar := tar.NewReader(gz)
	for {
		hdr, err := ar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		log.Printf("extracting file: %v", hdr.Name)
		if len(hdr.Name) == 0 || hdr.Name[len(hdr.Name)-1] == '/' {
			continue
		}
		base, file := filepath.Split(hdr.Name)
		if err := os.MkdirAll(filepath.Join(dir, base), 0700); err != nil {
			return err
		}
		dst, err := os.OpenFile(filepath.Join(dir, base, file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(dst, ar)
		dst.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func uploadFile(localFile string, gcsFile string) error {
	local, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer local.Close()
	pos := strings.IndexByte(gcsFile, '/')
	if pos == -1 {
		return fmt.Errorf("invalid GCS file name: %v", gcsFile)
	}
	bkt := storageClient.Bucket(gcsFile[:pos])
	f := bkt.Object(gcsFile[pos+1:])
	w := f.NewWriter(ctx)
	defer w.Close()
	io.Copy(w, local)
	return nil
}

func updateSyzkallerBuild() (string, error) {
	gopath, err := filepath.Abs("gopath")
	if err != nil {
		return "", err
	}
	goGet := exec.Command("go", "get", "-u", "-d", "github.com/google/syzkaller/syz-manager")
	goGet.Env = append([]string{"GOPATH=" + gopath}, os.Environ()...)
	if output, err := goGet.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}
	makeCmd := exec.Command("make")
	makeCmd.Env = append([]string{"GOPATH=" + gopath}, os.Environ()...)
	makeCmd.Dir = "gopath/src/github.com/google/syzkaller"
	if output, err := makeCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}
	return "gopath/src/github.com/google/syzkaller/bin", nil
}

func fatalf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
