// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-gce runs syz-manager on GCE in a continous loop handling image/syzkaller updates.
// It downloads test image from GCS, downloads and builds syzkaller, then starts syz-manager
// and pulls for image/syzkaller source updates. If image/syzkaller changes,
// it stops syz-manager and starts from scratch.
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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/gce"
	. "github.com/google/syzkaller/log"
	"golang.org/x/net/context"
)

var (
	flagConfig        = flag.String("config", "", "config file")
	flagNoImageCreate = flag.Bool("noimagecreate", false, "don't download/create image (for testing)")
	flagNoRebuild     = flag.Bool("norebuild", false, "don't update/rebuild syzkaller (for testing)")

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
	EnableLogCaching(1000, 1<<20)
	initHttp(fmt.Sprintf(":%v", cfg.Http_Port))

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

	sigC := make(chan os.Signal, 2)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGUSR1)

	var managerCmd *exec.Cmd
	managerStopped := make(chan error)
	stoppingManager := false
	var lastImageUpdated time.Time
	var lastSyzkallerHash string
	var delayDuration time.Duration
	for {
		if delayDuration != 0 {
			Logf(0, "sleep for %v", delayDuration)
			select {
			case <-time.After(delayDuration):
			case err := <-managerStopped:
				if managerCmd == nil {
					Fatalf("spurious manager stop signal")
				}
				Logf(0, "syz-manager exited with %v", err)
				managerCmd = nil
			case s := <-sigC:
				switch s {
				case syscall.SIGUSR1:
					// just poll for updates
					Logf(0, "SIGUSR1")
				case syscall.SIGINT:
					Logf(0, "SIGINT")
					if managerCmd != nil {
						Logf(0, "shutting down syz-manager...")
						managerCmd.Process.Signal(syscall.SIGINT)
						select {
						case err := <-managerStopped:
							if managerCmd == nil {
								Fatalf("spurious manager stop signal")
							}
							Logf(0, "syz-manager exited with %v", err)
						case <-sigC:
							managerCmd.Process.Kill()
						case <-time.After(time.Minute):
							managerCmd.Process.Kill()
						}
					}
					os.Exit(0)
				}
			}
		}
		delayDuration = 10 * time.Minute // assume that an error happened
		imageArchive, imageUpdated, err := openFile(cfg.Image_Archive)
		if err != nil {
			Logf(0, "%v", err)
			continue
		}
		syzkallerHash, err := updateSyzkallerBuild()
		if err != nil {
			Logf(0, "failed to update syzkaller: %v", err)
			continue
		}
		Logf(0, "image update time %v, syzkaller hash %v", imageUpdated, syzkallerHash)
		if lastImageUpdated == imageUpdated && lastSyzkallerHash == syzkallerHash && managerCmd != nil {
			delayDuration = time.Hour
			continue
		}

		if managerCmd != nil {
			if !stoppingManager {
				stoppingManager = true
				Logf(0, "stopping syz-manager...")
				managerCmd.Process.Signal(syscall.SIGINT)
			} else {
				Logf(0, "killing syz-manager...")
				managerCmd.Process.Kill()
			}
			delayDuration = time.Minute
			continue
		}

		if !*flagNoImageCreate && lastImageUpdated != imageUpdated {
			Logf(0, "downloading image archive...")
			if err := os.RemoveAll("image"); err != nil {
				Logf(0, "failed to remove image dir: %v", err)
				continue
			}
			if err := downloadAndExtract(imageArchive, "image"); err != nil {
				Logf(0, "failed to download and extract %v: %v", cfg.Image_Archive, err)
				continue
			}

			Logf(0, "uploading image...")
			if err := uploadFile("image/disk.tar.gz", cfg.Image_Path); err != nil {
				Logf(0, "failed to upload image: %v", err)
				continue
			}

			Logf(0, "creating gce image...")
			if err := GCE.DeleteImage(cfg.Image_Name); err != nil {
				Logf(0, "failed to delete GCE image: %v", err)
				continue
			}
			if err := GCE.CreateImage(cfg.Image_Name, cfg.Image_Path); err != nil {
				Logf(0, "failed to create GCE image: %v", err)
				continue
			}
		}
		*flagNoImageCreate = false
		lastImageUpdated = imageUpdated

		if !*flagNoRebuild && lastSyzkallerHash != syzkallerHash {
			Logf(0, "building syzkaller...")
			if err := buildSyzkaller(); err != nil {
				Logf(0, "failed to update/build syzkaller: %v", err)
				continue
			}
		}
		*flagNoRebuild = false
		lastSyzkallerHash = syzkallerHash

		if err := writeManagerConfig("manager.cfg"); err != nil {
			Logf(0, "failed to write manager config: %v", err)
			continue
		}

		Logf(0, "starting syz-manager (image %v, syzkaller %v)...", lastImageUpdated, lastSyzkallerHash)
		managerCmd = exec.Command("gopath/src/github.com/google/syzkaller/bin/syz-manager", "-config=manager.cfg")
		if err := managerCmd.Start(); err != nil {
			Logf(0, "failed to start syz-manager: %v", err)
			managerCmd = nil
			continue
		}
		stoppingManager = false
		go func() {
			managerStopped <- managerCmd.Wait()
		}()
		delayDuration = time.Hour
	}
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
	tag, err := ioutil.ReadFile("image/tag")
	if err != nil {
		return fmt.Errorf("failed to read tag file: %v", err)
	}
	if len(tag) != 0 && tag[len(tag)-1] == '\n' {
		tag = tag[:len(tag)-1]
	}
	managerCfg := &config.Config{
		Http:         fmt.Sprintf(":%v", cfg.Manager_Http_Port),
		Rpc:          ":0",
		Workdir:      "workdir",
		Vmlinux:      "image/obj/vmlinux",
		Tag:          string(tag),
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
	files := make(map[string]bool)
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
		files[filepath.Clean(hdr.Name)] = true
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
	for _, need := range []string{"disk.tar.gz", "key", "tag", "obj/vmlinux"} {
		if !files[need] {
			return fmt.Errorf("archive misses required file '%v'", need)
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

// updateSyzkallerBuild executes 'git pull' on syzkaller and all depenent packages.
// Returns syzkaller HEAD hash.
func updateSyzkallerBuild() (string, error) {
	goGet := exec.Command("go", "get", "-u", "-d", "github.com/google/syzkaller/syz-manager", "github.com/google/syzkaller/syz-gce")
	if output, err := goGet.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}

	gitCmd := exec.Command("git", "log", "--pretty=format:'%H'", "-n", "1")
	gitCmd.Dir = "gopath/src/github.com/google/syzkaller"
	output, err := gitCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v\n%s", err, output)
	}
	if len(output) != 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
	}
	if len(output) != 0 && output[0] == '\'' && output[len(output)-1] == '\'' {
		output = output[1 : len(output)-1]
	}
	if len(output) != 40 {
		return "", fmt.Errorf("unexpected git log output, want commit hash: %q", output)
	}
	return string(output), nil
}

func buildSyzkaller() error {
	makeCmd := exec.Command("make")
	makeCmd.Dir = "gopath/src/github.com/google/syzkaller"
	if output, err := makeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v\n%s", err, output)
	}
	return nil
}
