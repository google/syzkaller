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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/kd"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("gce", vmimpl.Type{
		Ctor:        ctor,
		Overcommit:  true,
		Preemptible: true,
	})
}

type Config struct {
	Count         int    `json:"count"`          // number of VMs to use
	ZoneID        string `json:"zone_id"`        // GCE zone (if it's different from that of syz-manager)
	MachineType   string `json:"machine_type"`   // GCE machine type (e.g. "n1-highcpu-2")
	GCSPath       string `json:"gcs_path"`       // GCS path to upload image
	GCEImage      string `json:"gce_image"`      // pre-created GCE image to use
	Preemptible   bool   `json:"preemptible"`    // use preemptible VMs if available (defaults to true)
	DisplayDevice bool   `json:"display_device"` // enable a virtual display device
	// Username to connect to ssh-serialport.googleapis.com.
	// Leave empty for non-OS Login GCP projects.
	// Otherwise take the user from `gcloud compute connect-to-serial-port --dry-run`.
	SerialPortUser string `json:"serial_port_user"`
	// A private key to connect to ssh-serialport.googleapis.com.
	// Leave empty for non-OS Login GCP projects.
	// Otherwise generate one and upload it:
	// `gcloud compute os-login ssh-keys add --key-file some-key.pub`.
	SerialPortKey string   `json:"serial_port_key"`
	Tags          []string `json:"tags"` // GCE instance tags
}

type Pool struct {
	env            *vmimpl.Env
	cfg            *Config
	GCE            *gce.Context
	consoleReadCmd string // optional: command to read non-standard kernel console
}

type instance struct {
	env   *vmimpl.Env
	cfg   *Config
	GCE   *gce.Context
	debug bool
	name  string
	vmimpl.SSHOptions
	gceKey         string // per-instance private ssh key associated with the instance
	closed         chan bool
	consolew       io.WriteCloser
	consoleReadCmd string // optional: command to read non-standard kernel console
	timeouts       targets.Timeouts
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	return Ctor(env, "")
}

func Ctor(env *vmimpl.Env, consoleReadCmd string) (*Pool, error) {
	if env.Name == "" {
		return nil, fmt.Errorf("config param name is empty (required for GCE)")
	}
	cfg := &Config{
		Count:       1,
		Preemptible: true,
		// Display device is not supported on other platforms.
		DisplayDevice: env.Arch == targets.AMD64,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse gce vm config: %w", err)
	}
	if cfg.Count < 1 || cfg.Count > 1000 {
		return nil, fmt.Errorf("invalid config param count: %v, want [1, 1000]", cfg.Count)
	}
	if cfg.MachineType == "" {
		return nil, fmt.Errorf("machine_type parameter is empty")
	}
	if cfg.GCEImage == "" && cfg.GCSPath == "" {
		return nil, fmt.Errorf("gcs_path parameter is empty")
	}
	if cfg.GCEImage == "" && env.Image == "" {
		return nil, fmt.Errorf("config param image is empty (required for GCE)")
	}
	if cfg.GCEImage != "" && env.Image != "" {
		return nil, fmt.Errorf("both image and gce_image are specified")
	}

	GCE, err := initGCE(cfg.ZoneID)
	if err != nil {
		return nil, err
	}

	log.Logf(0, "GCE initialized: running on %v, internal IP %v, project %v, zone %v, net %v/%v",
		GCE.Instance, GCE.InternalIP, GCE.ProjectID, GCE.ZoneID, GCE.Network, GCE.Subnetwork)

	if cfg.GCEImage == "" {
		cfg.GCEImage = env.Name
		gcsImage := filepath.Join(cfg.GCSPath, env.Name+"-image.tar.gz")
		log.Logf(0, "uploading image %v to %v...", env.Image, gcsImage)
		if err := uploadImageToGCS(env.Image, gcsImage); err != nil {
			return nil, err
		}
		log.Logf(0, "creating GCE image %v...", cfg.GCEImage)
		if err := GCE.DeleteImage(cfg.GCEImage); err != nil {
			return nil, fmt.Errorf("failed to delete GCE image: %w", err)
		}
		if err := GCE.CreateImage(cfg.GCEImage, gcsImage, env.OS); err != nil {
			return nil, fmt.Errorf("failed to create GCE image: %w", err)
		}
	}
	pool := &Pool{
		cfg:            cfg,
		env:            env,
		GCE:            GCE,
		consoleReadCmd: consoleReadCmd,
	}
	return pool, nil
}

func initGCE(zoneID string) (*gce.Context, error) {
	// There happen some transient GCE init errors on and off.
	// Let's try it several times before aborting.
	const (
		gceInitAttempts = 3
		gceInitBackoff  = 5 * time.Second
	)
	var (
		GCE *gce.Context
		err error
	)
	for i := 1; i <= gceInitAttempts; i++ {
		if i > 1 {
			time.Sleep(gceInitBackoff)
		}
		GCE, err = gce.NewContext(zoneID)
		if err == nil {
			return GCE, nil
		}
		log.Logf(0, "init GCE attempt %d/%d failed: %v", i, gceInitAttempts, err)
	}
	return nil, fmt.Errorf("all attempts to init GCE failed: %w", err)
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	name := fmt.Sprintf("%v-%v", pool.env.Name, index)
	// Create SSH key for the instance.
	gceKey := filepath.Join(workdir, "key")
	keygen := osutil.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "syzkaller", "-f", gceKey)
	if out, err := keygen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %w\n%s", err, out)
	}
	gceKeyPub, err := os.ReadFile(gceKey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	log.Logf(0, "deleting instance: %v", name)
	if err := pool.GCE.DeleteInstance(name, true); err != nil {
		return nil, err
	}
	log.Logf(0, "creating instance: %v", name)
	ip, err := pool.GCE.CreateInstance(name, pool.cfg.MachineType, pool.cfg.GCEImage,
		string(gceKeyPub), pool.cfg.Tags, pool.cfg.Preemptible, pool.cfg.DisplayDevice)
	if err != nil {
		return nil, err
	}

	ok := false
	defer func() {
		if !ok {
			pool.GCE.DeleteInstance(name, true)
		}
	}()
	sshKey := pool.env.SSHKey
	sshUser := pool.env.SSHUser
	if sshKey == "GCE" {
		// Assuming image supports GCE ssh fanciness.
		sshKey = gceKey
		sshUser = "syzkaller"
	}
	log.Logf(0, "wait instance to boot: %v (%v)", name, ip)
	inst := &instance{
		env:   pool.env,
		cfg:   pool.cfg,
		debug: pool.env.Debug,
		GCE:   pool.GCE,
		name:  name,
		SSHOptions: vmimpl.SSHOptions{
			Addr: ip,
			Port: 22,
			Key:  sshKey,
			User: sshUser,
		},

		gceKey: gceKey,

		closed:         make(chan bool),
		consoleReadCmd: pool.consoleReadCmd,
		timeouts:       pool.env.Timeouts,
	}
	if err := vmimpl.WaitForSSH(5*time.Minute, inst.SSHOptions,
		pool.env.OS, nil, false, pool.env.Debug); err != nil {
		output, outputErr := inst.getSerialPortOutput()
		if outputErr != nil {
			output = []byte(fmt.Sprintf("failed to get boot output: %v", outputErr))
		}
		return nil, vmimpl.MakeBootError(err, output)
	}
	ok = true
	return inst, nil
}

func (inst *instance) Close() error {
	close(inst.closed)
	err := inst.GCE.DeleteInstance(inst.name, false)
	if inst.consolew != nil {
		err2 := inst.consolew.Close()
		if err == nil {
			err = err2
		}
	}
	return err
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", inst.GCE.InternalIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := "./" + filepath.Base(hostSrc)
	args := append(vmimpl.SCPArgs(true, inst.Key, inst.Port, false),
		hostSrc, inst.User+"@"+inst.Addr+":"+vmDst)
	if err := runCmd(inst.debug, "scp", args...); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	conRpipe, conWpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	var conArgs []string
	if inst.consoleReadCmd == "" {
		conArgs = inst.serialPortArgs(false)
	} else {
		conArgs = inst.sshArgs(inst.consoleReadCmd)
	}
	con := osutil.Command("ssh", conArgs...)
	con.Env = []string{}
	con.Stdout = conWpipe
	con.Stderr = conWpipe
	conw, err := con.StdinPipe()
	if err != nil {
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, err
	}
	if inst.consolew != nil {
		inst.consolew.Close()
	}
	inst.consolew = conw
	if err := con.Start(); err != nil {
		conRpipe.Close()
		conWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to console server: %w", err)
	}
	conWpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	var decoder func(data []byte) (int, int, []byte)
	if inst.env.OS == targets.Windows {
		decoder = kd.Decode
	}
	merger.AddDecoder("console", vmimpl.OutputConsole, conRpipe, decoder)
	if err := waitForConsoleConnect(merger); err != nil {
		con.Process.Kill()
		merger.Wait()
		return nil, nil, err
	}
	sshRpipe, sshWpipe, err := osutil.LongPipe()
	if err != nil {
		con.Process.Kill()
		merger.Wait()
		sshRpipe.Close()
		return nil, nil, err
	}
	ssh := osutil.Command("ssh", inst.sshArgs(command)...)
	ssh.Stdout = sshWpipe
	ssh.Stderr = sshWpipe
	if err := ssh.Start(); err != nil {
		con.Process.Kill()
		merger.Wait()
		sshRpipe.Close()
		sshWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to instance: %w", err)
	}
	sshWpipe.Close()
	merger.Add("ssh", vmimpl.OutputCommand, sshRpipe)

	return vmimpl.Multiplex(ctx, ssh, merger, vmimpl.MultiplexConfig{
		Console: vmimpl.CmdCloser{Cmd: con},
		Close:   inst.closed,
		Debug:   inst.debug,
		Scale:   inst.timeouts.Scale,
		IgnoreError: func(err error) bool {
			var mergeError *vmimpl.MergerError
			if errors.As(err, &mergeError) && mergeError.R == conRpipe {
				// Console connection must never fail. If it does, it's either
				// instance preemption or a GCE bug. In either case, not a kernel bug.
				log.Logf(0, "%v: gce console connection failed with %v", inst.name, mergeError.Err)
				return true
			} else {
				// Check if the instance was terminated due to preemption or host maintenance.
				// vmimpl.Multiplex() already adds a delay, so we've already waited enough
				// to let GCE VM status updates propagate.
				if !inst.GCE.IsInstanceRunning(inst.name) {
					log.Logf(0, "%v: ssh exited but instance is not running", inst.name)
					return true
				}
			}
			return false
		},
	})
}

func waitForConsoleConnect(merger *vmimpl.OutputMerger) error {
	// We've started the console reading ssh command, but it has not necessary connected yet.
	// If we proceed to running the target command right away, we can miss part
	// of console output. During repro we can crash machines very quickly and
	// would miss beginning of a crash. Before ssh starts piping console output,
	// it usually prints:
	// "serialport: Connected to ... port 1 (session ID: ..., active connections: 1)"
	// So we wait for this line, or at least a minute and at least some output.
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	connectedMsg := []byte("serialport: Connected")
	permissionDeniedMsg := []byte("Permission denied (publickey)")
	var output []byte
	for {
		select {
		case out := <-merger.Output:
			output = append(output, out.Data...)
			if bytes.Contains(output, connectedMsg) {
				// Just to make sure (otherwise we still see trimmed reports).
				time.Sleep(5 * time.Second)
				return nil
			}
			if bytes.Contains(output, permissionDeniedMsg) {
				// This is a GCE bug.
				return fmt.Errorf("broken console: %s", permissionDeniedMsg)
			}
		case <-timeout.C:
			if len(output) == 0 {
				return fmt.Errorf("broken console: no output")
			}
			return nil
		}
	}
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	switch inst.env.OS {
	case targets.Linux:
		output, wait, _ := vmimpl.DiagnoseLinux(rep, inst.ssh)
		return output, wait
	case targets.FreeBSD:
		return vmimpl.DiagnoseFreeBSD(inst.consolew)
	case targets.OpenBSD:
		return vmimpl.DiagnoseOpenBSD(inst.consolew)
	}
	return nil, false
}

func (inst *instance) ssh(args ...string) ([]byte, error) {
	return osutil.RunCmd(time.Minute, "", "ssh", inst.sshArgs(args...)...)
}

func (inst *instance) sshArgs(args ...string) []string {
	sshArgs := append(vmimpl.SSHArgs(inst.debug, inst.Key, 22, false), inst.User+"@"+inst.Addr)
	if inst.env.OS == targets.Linux && inst.User != "root" {
		args = []string{"sudo", "bash", "-c", "'" + strings.Join(args, " ") + "'"}
	}
	return append(sshArgs, args...)
}

func (inst *instance) serialPortArgs(replay bool) []string {
	user := "syzkaller"
	if inst.cfg.SerialPortUser != "" {
		user = inst.cfg.SerialPortUser
	}
	key := inst.gceKey
	if inst.cfg.SerialPortKey != "" {
		key = inst.cfg.SerialPortKey
	}
	replayArg := ""
	if replay {
		replayArg = ".replay-lines=10000"
	}
	conAddr := fmt.Sprintf("%v.%v.%v.%s.port=1%s@%v-ssh-serialport.googleapis.com",
		inst.GCE.ProjectID, inst.GCE.ZoneID, inst.name, user, replayArg, inst.GCE.RegionID)
	conArgs := append(vmimpl.SSHArgs(inst.debug, key, 9600, false), conAddr)
	// TODO(blackgnezdo): Remove this once ssh-serialport.googleapis.com stops using
	// host key algorithm: ssh-rsa.
	return append(conArgs, "-o", "HostKeyAlgorithms=+ssh-rsa")
}

func (inst *instance) getSerialPortOutput() ([]byte, error) {
	conRpipe, conWpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, err
	}
	defer conRpipe.Close()
	defer conWpipe.Close()

	con := osutil.Command("ssh", inst.serialPortArgs(true)...)
	con.Env = []string{}
	con.Stdout = conWpipe
	con.Stderr = conWpipe
	if _, err := con.StdinPipe(); err != nil { // SSH would close connection on stdin EOF
		return nil, err
	}
	if err := con.Start(); err != nil {
		return nil, fmt.Errorf("failed to connect to console server: %w", err)
	}
	conWpipe.Close()
	done := make(chan bool)
	go func() {
		timeout := time.NewTimer(time.Minute)
		defer timeout.Stop()
		select {
		case <-done:
		case <-timeout.C:
		}
		con.Process.Kill()
	}()
	var output []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := conRpipe.Read(buf)
		if err != nil || n == 0 {
			break
		}
		output = append(output, buf[:n]...)
	}
	close(done)
	con.Wait()
	return output, nil
}

func uploadImageToGCS(localImage, gcsImage string) error {
	GCS, err := gcs.NewClient(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer GCS.Close()

	localReader, err := os.Open(localImage)
	if err != nil {
		return fmt.Errorf("failed to open image file: %w", err)
	}
	defer localReader.Close()
	localStat, err := localReader.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat image file: %w", err)
	}

	gcsWriter, err := GCS.FileWriter(gcsImage, "", "")
	if err != nil {
		return fmt.Errorf("failed to upload image: %w", err)
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
		Uname:    "syzkaller",
		Gname:    "syzkaller",
	}
	setGNUFormat(tarHeader)
	if err := tarWriter.WriteHeader(tarHeader); err != nil {
		return fmt.Errorf("failed to write image tar header: %w", err)
	}
	if _, err := io.Copy(tarWriter, localReader); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}
	if err := gcsWriter.Close(); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}
	return nil
}

func runCmd(debug bool, bin string, args ...string) error {
	if debug {
		log.Logf(0, "running command: %v %#v", bin, args)
	}
	output, err := osutil.RunCmd(time.Minute, "", bin, args...)
	if debug {
		log.Logf(0, "result: %v\n%s", err, output)
	}
	return err
}
