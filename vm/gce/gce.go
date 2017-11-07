// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gce allows to use Google Compute Engine (GCE) virtual machines as VMs.
// It is assumed that syz-manager also runs on GCE as VMs are created in the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, how to build GCE-compatible images:
// https://cloud.google.com/compute/docs/tutorials/building-images
// Working with serial console:
// https://cloud.google.com/compute/docs/instances/interacting-with-serial-console
package gce

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/kd"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("gce", ctor)
}

type Config struct {
	Count        int    // number of VMs to use
	Machine_Type string // GCE machine type (e.g. "n1-highcpu-2")
	GCS_Path     string // GCS path to upload image
	GCE_Image    string // Pre-created GCE image to use
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
	GCE *gce.Context
}

type instance struct {
	env     *vmimpl.Env
	cfg     *Config
	GCE     *gce.Context
	debug   bool
	name    string
	ip      string
	offset  int64
	gceKey  string // per-instance private ssh key associated with the instance
	sshKey  string // ssh key
	sshUser string
	workdir string
	closed  chan bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	if env.Name == "" {
		return nil, fmt.Errorf("config param name is empty (required for GCE)")
	}
	cfg := &Config{
		Count: 1,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse gce vm config: %v", err)
	}
	if cfg.Count < 1 || cfg.Count > 1000 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if env.Debug {
		cfg.Count = 1
	}
	if cfg.Machine_Type == "" {
		return nil, fmt.Errorf("machine_type parameter is empty")
	}
	if cfg.GCE_Image == "" && cfg.GCS_Path == "" {
		return nil, fmt.Errorf("gcs_path parameter is empty")
	}
	if cfg.GCE_Image == "" && env.Image == "" {
		return nil, fmt.Errorf("config param image is empty (required for GCE)")
	}
	if cfg.GCE_Image != "" && env.Image != "" {
		return nil, fmt.Errorf("both image and gce_image are specified")
	}

	GCE, err := gce.NewContext()
	if err != nil {
		return nil, fmt.Errorf("failed to init gce: %v", err)
	}
	Logf(0, "GCE initialized: running on %v, internal IP %v, project %v, zone %v",
		GCE.Instance, GCE.InternalIP, GCE.ProjectID, GCE.ZoneID)

	if cfg.GCE_Image == "" {
		cfg.GCE_Image = env.Name
		gcsImage := filepath.Join(cfg.GCS_Path, env.Name+"-image.tar.gz")
		Logf(0, "uploading image to %v...", gcsImage)
		if err := uploadImageToGCS(env.Image, gcsImage); err != nil {
			return nil, err
		}
		Logf(0, "creating GCE image %v...", cfg.GCE_Image)
		if err := GCE.DeleteImage(cfg.GCE_Image); err != nil {
			return nil, fmt.Errorf("failed to delete GCE image: %v", err)
		}
		if err := GCE.CreateImage(cfg.GCE_Image, gcsImage); err != nil {
			return nil, fmt.Errorf("failed to create GCE image: %v", err)
		}
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
		GCE: GCE,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	name := fmt.Sprintf("%v-%v", pool.env.Name, index)
	// Create SSH key for the instance.
	gceKey := filepath.Join(workdir, "key")
	keygen := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-C", "syzkaller", "-f", gceKey)
	if out, err := keygen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %v\n%s", err, out)
	}
	gceKeyPub, err := ioutil.ReadFile(gceKey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	Logf(0, "deleting instance: %v", name)
	if err := pool.GCE.DeleteInstance(name, true); err != nil {
		return nil, err
	}
	Logf(0, "creating instance: %v", name)
	ip, err := pool.GCE.CreateInstance(name, pool.cfg.Machine_Type, pool.cfg.GCE_Image, string(gceKeyPub))
	if err != nil {
		return nil, err
	}

	ok := false
	defer func() {
		if !ok {
			pool.GCE.DeleteInstance(name, true)
		}
	}()
	sshKey := pool.env.SshKey
	sshUser := pool.env.SshUser
	if sshKey == "" {
		// Assuming image supports GCE ssh fanciness.
		sshKey = gceKey
		sshUser = "syzkaller"
	}
	Logf(0, "wait instance to boot: %v (%v)", name, ip)
	if err := pool.waitInstanceBoot(ip, sshKey, sshUser); err != nil {
		return nil, err
	}
	ok = true
	inst := &instance{
		env:     pool.env,
		cfg:     pool.cfg,
		debug:   pool.env.Debug,
		GCE:     pool.GCE,
		name:    name,
		ip:      ip,
		gceKey:  gceKey,
		sshKey:  sshKey,
		sshUser: sshUser,
		closed:  make(chan bool),
	}
	return inst, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	inst.GCE.DeleteInstance(inst.name, false)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", inst.GCE.InternalIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := "./" + filepath.Base(hostSrc)
	args := append(sshArgs(inst.debug, inst.sshKey, "-P", 22), hostSrc, inst.sshUser+"@"+inst.name+":"+vmDst)
	if _, err := runCmd(inst.debug, "scp", args...); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	conRpipe, conWpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	conAddr := fmt.Sprintf("%v.%v.%v.syzkaller.port=1@ssh-serialport.googleapis.com",
		inst.GCE.ProjectID, inst.GCE.ZoneID, inst.name)
	conArgs := append(sshArgs(inst.debug, inst.gceKey, "-p", 9600), conAddr)
	con := exec.Command("ssh", conArgs...)
	con.Env = []string{}
	con.Stdout = conWpipe
	con.Stderr = conWpipe
	if _, err := con.StdinPipe(); err != nil { // SSH would close connection on stdin EOF
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, err
	}
	if err := con.Start(); err != nil {
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to console server: %v", err)

	}
	conWpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	var decoder func(data []byte) (int, int, []byte)
	if inst.env.OS == "windows" {
		decoder = kd.Decode
	}
	merger.AddDecoder("console", conRpipe, decoder)

	// We've started the console reading ssh command, but it has not necessary connected yet.
	// If we proceed to running the target command right away, we can miss part
	// of console output. During repro we can crash machines very quickly and
	// would miss beginning of a crash. Before ssh starts piping console output,
	// it usually prints:
	// "serialport: Connected to ... port 1 (session ID: ..., active connections: 1)"
	// So we wait for this line, or at least a minute and at least some output.
	{
		var output []byte
		timeout := time.NewTimer(time.Minute)
		connectedMsg := []byte("serialport: Connected")
		permissionDeniedMsg := []byte("Permission denied (publickey)")
	loop:
		for {
			select {
			case out := <-merger.Output:
				output = append(output, out...)
				if bytes.Contains(output, connectedMsg) {
					// Just to make sure (otherwise we still see trimmed reports).
					time.Sleep(5 * time.Second)
					break loop
				}
				if bytes.Contains(output, permissionDeniedMsg) {
					// This is a GCE bug.
					break
				}
			case <-timeout.C:
				break loop
			}
		}
		timeout.Stop()
		if len(output) == 0 || bytes.Contains(output, permissionDeniedMsg) {
			con.Process.Kill()
			merger.Wait()
			return nil, nil, fmt.Errorf("no output from console or permission denied")
		}
	}

	sshRpipe, sshWpipe, err := osutil.LongPipe()
	if err != nil {
		con.Process.Kill()
		merger.Wait()
		sshRpipe.Close()
		return nil, nil, err
	}
	if inst.env.OS == "linux" {
		if inst.sshUser != "root" {
			command = fmt.Sprintf("sudo bash -c '%v'", command)
		}
	}
	args := append(sshArgs(inst.debug, inst.sshKey, "-p", 22), inst.sshUser+"@"+inst.name, command)
	ssh := exec.Command("ssh", args...)
	ssh.Stdout = sshWpipe
	ssh.Stderr = sshWpipe
	if err := ssh.Start(); err != nil {
		con.Process.Kill()
		merger.Wait()
		sshRpipe.Close()
		sshWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to instance: %v", err)
	}
	sshWpipe.Close()
	merger.Add("ssh", sshRpipe)

	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vmimpl.TimeoutErr)
		case <-stop:
			signal(vmimpl.TimeoutErr)
		case <-inst.closed:
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			con.Process.Kill()
			ssh.Process.Kill()
			merger.Wait()
			con.Wait()
			if cmdErr := ssh.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			} else {
				// Check if the instance was terminated due to preemption or host maintenance.
				time.Sleep(5 * time.Second) // just to avoid any GCE races
				if !inst.GCE.IsInstanceRunning(inst.name) {
					Logf(1, "%v: ssh exited but instance is not running", inst.name)
					err = vmimpl.TimeoutErr
				}
			}
			signal(err)
			return
		}
		con.Process.Kill()
		ssh.Process.Kill()
		merger.Wait()
		con.Wait()
		ssh.Wait()
	}()
	return merger.Output, errc, nil
}

func (pool *Pool) waitInstanceBoot(ip, sshKey, sshUser string) error {
	pwd := "pwd"
	if pool.env.OS == "windows" {
		pwd = "dir"
	}
	for i := 0; i < 100; i++ {
		if !vmimpl.SleepInterruptible(5 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		args := append(sshArgs(pool.env.Debug, sshKey, "-p", 22), sshUser+"@"+ip, pwd)
		if _, err := runCmd(pool.env.Debug, "ssh", args...); err == nil {
			return nil
		}
	}
	return fmt.Errorf("can't ssh into the instance")
}

func uploadImageToGCS(localImage, gcsImage string) error {
	GCS, err := gcs.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %v", err)
	}
	defer GCS.Close()

	localReader, err := os.Open(localImage)
	if err != nil {
		return fmt.Errorf("failed to open image file: %v", err)
	}
	defer localReader.Close()
	localStat, err := localReader.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat image file: %v", err)
	}

	gcsWriter, err := GCS.FileWriter(gcsImage)
	if err != nil {
		return fmt.Errorf("failed to upload image: %v", err)
	}
	defer gcsWriter.Close()

	gzipWriter := gzip.NewWriter(gcsWriter)
	tarWriter := tar.NewWriter(gzipWriter)
	tarHeader := &tar.Header{
		Name:     "disk.raw",
		Typeflag: tar.TypeReg,
		Mode:     0640,
		Size:     localStat.Size(),
		ModTime:  time.Now(),
		// This is hacky but we actually need these large uids.
		// GCE understands only the old GNU tar format and
		// there is no direct way to force tar package to use GNU format.
		// But these large numbers force tar to switch to GNU format.
		Uid:   100000000,
		Gid:   100000000,
		Uname: "syzkaller",
		Gname: "syzkaller",
	}
	if err := tarWriter.WriteHeader(tarHeader); err != nil {
		return fmt.Errorf("failed to write image tar header: %v", err)
	}
	if _, err := io.Copy(tarWriter, localReader); err != nil {
		return fmt.Errorf("failed to write image file: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %v", err)
	}
	if err := gcsWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %v", err)
	}
	return nil
}

func runCmd(debug bool, bin string, args ...string) ([]byte, error) {
	if debug {
		Logf(0, "running command: %v %#v", bin, args)
	}
	output, err := osutil.RunCmd(time.Minute, "", bin, args...)
	if debug {
		Logf(0, "result: %v\n%s", err, output)
	}
	return output, err
}

func sshArgs(debug bool, sshKey, portArg string, port int) []string {
	args := []string{
		portArg, fmt.Sprint(port),
		"-i", sshKey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
	}
	if debug {
		args = append(args, "-v")
	}
	return args
}
