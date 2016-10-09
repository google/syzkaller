// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/gce"
	. "github.com/google/syzkaller/log"
	"golang.org/x/net/context"
)

var (
	flagConfig = flag.String("config", "", "config file")

	cfg           *Config
	ctx           context.Context
	storageClient *storage.Client
	GCE           *gce.Context
)

type Config struct {
	Image_Archive     string
	Image_Path        string
	Image_Name        string
	Http_Port         int
	Manager_Http_Port int
	Machine_Type      string
	Machine_Count     int
	Sandbox           string
	Procs             int
}

func main() {
	flag.Parse()
	cfg = readConfig(*flagConfig)

	gopath, err := filepath.Abs("gopath")
	if err != nil {
		Fatalf("failed to get absolute path: %v", err)
	}
	os.Setenv("GOPATH", gopath)

	ctx = context.Background()
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		Fatalf("failed to create cloud storage client: %v", err)
	}

	GCE, err = gce.NewContext()
	if err != nil {
		Fatalf("failed to init gce: %v", err)
	}
	Logf(0, "gce initialized: running on %v, internal IP, %v project %v, zone %v", GCE.Instance, GCE.InternalIP, GCE.ProjectID, GCE.ZoneID)

	Logf(0, "downloading image archive...")
	archive, updated, err := openFile(cfg.Image_Archive)
	if err != nil {
		Fatalf("%v", err)
	}
	_ = updated
	if err := os.RemoveAll("image"); err != nil {
		Fatalf("failed to remove image dir: %v", err)
	}
	if err := downloadAndExtract(archive, "image"); err != nil {
		Fatalf("failed to download and extract %v: %v", cfg.Image_Archive, err)
	}

	Logf(0, "uploading image...")
	if err := uploadFile("image/disk.tar.gz", cfg.Image_Path); err != nil {
		Fatalf("failed to upload image: %v", err)
	}

	Logf(0, "creating gce image...")
	if err := GCE.DeleteImage(cfg.Image_Name); err != nil {
		Fatalf("failed to delete GCE image: %v", err)
	}
	if err := GCE.CreateImage(cfg.Image_Name, cfg.Image_Path); err != nil {
		Fatalf("failed to create GCE image: %v", err)
	}

	Logf(0, "building syzkaller...")
	syzBin, err := updateSyzkallerBuild()
	if err != nil {
		Fatalf("failed to update/build syzkaller: %v", err)
	}
	_ = syzBin

	Logf(0, "starting syzkaller...")
	if err := writeManagerConfig("manager.cfg"); err != nil {
		Fatalf("failed to write manager config: %v", err)
	}

	manager := exec.Command("gopath/src/github.com/google/syzkaller/bin/syz-manager", "-config=manager.cfg")
	manager.Stdout = os.Stdout
	manager.Stderr = os.Stderr
	if err := manager.Start(); err != nil {
		Fatalf("failed to start syz-manager: %v", err)
	}
	err = manager.Wait()
	Fatalf("syz-manager exited with: %v", err)
}

func readConfig(filename string) *Config {
	if filename == "" {
		Fatalf("supply config in -config flag")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		Fatalf("failed to read config file: %v", err)
	}
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		Fatalf("failed to parse config file: %v", err)
	}
	return cfg
}

func writeManagerConfig(file string) error {
	managerCfg := &config.Config{
		Http:         fmt.Sprintf(":%v", cfg.Manager_Http_Port),
		Rpc:          ":0",
		Workdir:      "workdir",
		Vmlinux:      "image/obj/vmlinux",
		Syzkaller:    "gopath/src/github.com/google/syzkaller",
		Type:         "gce",
		Machine_Type: cfg.Machine_Type,
		Count:        cfg.Machine_Count,
		Image:        cfg.Image_Name,
		Sshkey:       "image/key",
		Sandbox:      cfg.Sandbox,
		Procs:        cfg.Procs,
		Cover:        true,
	}
	data, err := json.MarshalIndent(managerCfg, "", "\t")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(file, data, 0600); err != nil {
		return err
	}
	return nil
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
		Logf(0, "extracting file: %v (%v bytes)", hdr.Name, hdr.Size)
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
	goGet := exec.Command("go", "get", "-u", "-d", "github.com/google/syzkaller/syz-manager", "github.com/google/syzkaller/syz-gce")
	if output, err := goGet.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}
	makeCmd := exec.Command("make")
	makeCmd.Dir = "gopath/src/github.com/google/syzkaller"
	if output, err := makeCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}
	return "gopath/src/github.com/google/syzkaller/bin", nil
}
