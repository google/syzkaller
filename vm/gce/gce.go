// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gce allows to use Google Compute Engine (GCE) virtual machines as VMs.
// It is assumed that syz-manager also runs on GCE as VMs are created in the current project/zone.
// See https://cloud.google.com/compute/docs for details.
// In particular, how to build GCE-compatible images:
// https://cloud.google.com/compute/docs/tutorials/building-images
// Working with serial console:
// https://cloud.google.com/compute/docs/instances/interacting-with-serial-console
// API reference:
// https://cloud.google.com/compute/docs/reference/latest/
// and Go API wrappers:
// https://godoc.org/google.golang.org/api/compute/v0.beta
package gce

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/vm"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v0.beta"
	"google.golang.org/api/googleapi"
)

func init() {
	vm.Register("gce", ctor)
}

type instance struct {
	cfg     *vm.Config
	name    string
	ip      string
	offset  int64
	sshkey  string // per-instance private ssh key
	workdir string
	closed  chan bool
}

var (
	initOnce       sync.Once
	computeService *compute.Service
	projectID      string
	zoneID         string
	internalIP     string

	// apiCallTicker ticks regularly, preventing us from accidentally making
	// GCE API calls too quickly. Our quota is 20 QPS, but we temporarily
	// limit ourselves to less than that.
	apiRateGate = time.NewTicker(time.Second / 10).C
)

func initGCE() {
	ctx := context.Background()
	tokenSource, err := google.DefaultTokenSource(ctx, compute.CloudPlatformScope)
	if err != nil {
		log.Fatalf("failed to get a token source: %v", err)
	}
	httpClient := oauth2.NewClient(ctx, tokenSource)
	computeService, _ = compute.New(httpClient)
	// Obtain project name, zone and current instance IP address.
	projectID, err = getMeta("project/project-id")
	if err != nil {
		log.Fatalf("failed to query gce project-id: %v", err)
	}
	zoneID, err = getMeta("instance/zone")
	if err != nil {
		log.Fatalf("failed to query gce zone: %v", err)
	}
	if i := strings.LastIndexByte(zoneID, '/'); i != -1 {
		zoneID = zoneID[i+1:] // the query returns some nonsense prefix
	}
	instID, err := getMeta("instance/id")
	if err != nil {
		log.Fatalf("failed to query gce instance id: %v", err)
	}
	instances, err := computeService.Instances.List(projectID, zoneID).Do()
	if err != nil {
		log.Fatalf("error getting instance list: %v", err)
	}
	// Finds this instance internal IP.
	instName := ""
	for _, inst := range instances.Items {
		if fmt.Sprint(inst.Id) != instID {
			continue
		}
		instName = inst.Name
		for _, iface := range inst.NetworkInterfaces {
			if strings.HasPrefix(iface.NetworkIP, "10.") {
				internalIP = iface.NetworkIP
				break
			}
		}
		break
	}
	if instName == "" || internalIP == "" {
		log.Fatalf("failed to get current instance name and internal IP")
	}
	log.Printf("gce initialized: running on %v, internal IP, %v project %v, zone %v", instName, internalIP, projectID, zoneID)
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	initOnce.Do(initGCE)
	name := fmt.Sprintf("syzkaller-%v", cfg.Index)
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(cfg.Workdir)
		}
	}()

	// Create SSH key for the instance.
	sshkey := filepath.Join(cfg.Workdir, "key")
	keygen := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-C", "syzkaller", "-f", sshkey)
	if out, err := keygen.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to execute ssh-keygen: %v\n%s", err, out)
	}
	sshkeyPub, err := ioutil.ReadFile(sshkey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	log.Printf("deleting instance: %v", name)
	if err := deleteInstance(name); err != nil {
		return nil, err
	}
	log.Printf("creating instance: %v", name)
	ip, err := createInstance(name, cfg.MachineType, cfg.Image, string(sshkeyPub))
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			deleteInstance(name)
		}
	}()
	log.Printf("wait instance to boot: %v (%v)", name, ip)
	if err := waitInstanceBoot(ip, cfg.Sshkey); err != nil {
		return nil, err
	}
	ok = true
	inst := &instance{
		cfg:    cfg,
		name:   name,
		ip:     ip,
		sshkey: sshkey,
		closed: make(chan bool),
	}
	return inst, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	deleteInstance(inst.name)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", internalIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/", filepath.Base(hostSrc))
	args := append(sshArgs(inst.cfg.Sshkey, "-P", 22), hostSrc, "root@"+inst.name+":"+vmDst)
	cmd := exec.Command("scp", args...)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	conRpipe, conWpipe, err := vm.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	conAddr := fmt.Sprintf("%v.%v.%v.syzkaller.port=1@ssh-serialport.googleapis.com", projectID, zoneID, inst.name)
	conArgs := append(sshArgs(inst.sshkey, "-p", 9600), conAddr)
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
	conDone := make(chan error, 1)
	go func() {
		err := con.Wait()
		conDone <- fmt.Errorf("console connection closed: %v", err)
	}()

	sshRpipe, sshWpipe, err := vm.LongPipe()
	if err != nil {
		con.Process.Kill()
		sshRpipe.Close()
		return nil, nil, err
	}
	args := append(sshArgs(inst.cfg.Sshkey, "-p", 22), "root@"+inst.name, command)
	ssh := exec.Command("ssh", args...)
	ssh.Stdout = sshWpipe
	ssh.Stderr = sshWpipe
	if err := ssh.Start(); err != nil {
		con.Process.Kill()
		conRpipe.Close()
		sshRpipe.Close()
		sshWpipe.Close()
		return nil, nil, fmt.Errorf("failed to connect to instance: %v", err)
	}
	sshWpipe.Close()
	sshDone := make(chan error, 1)
	go func() {
		err := ssh.Wait()
		sshDone <- fmt.Errorf("ssh exited: %v", err)
	}()

	merger := vm.NewOutputMerger(nil)
	merger.Add(conRpipe)
	merger.Add(sshRpipe)

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
			signal(vm.TimeoutErr)
			con.Process.Kill()
			ssh.Process.Kill()
		case <-inst.closed:
			signal(fmt.Errorf("instance closed"))
			con.Process.Kill()
			ssh.Process.Kill()
		case err := <-conDone:
			signal(err)
			ssh.Process.Kill()
		case err := <-sshDone:
			signal(err)
			con.Process.Kill()
		}
		merger.Wait()
	}()
	return merger.Output, errc, nil
}

func getMeta(path string) (string, error) {
	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func waitInstanceBoot(ip, sshkey string) error {
	for i := 0; i < 100; i++ {
		if !vm.SleepInterruptible(5 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		cmd := exec.Command("ssh", append(sshArgs(sshkey, "-p", 22), "root@"+ip, "pwd")...)
		if _, err := cmd.CombinedOutput(); err == nil {
			return nil
		}
	}
	return fmt.Errorf("can't ssh into the instance")
}

func createInstance(name, machineType, image, sshkey string) (string, error) {
	prefix := "https://www.googleapis.com/compute/v1/projects/" + projectID
	instance := &compute.Instance{
		Name:        name,
		Description: "syzkaller worker",
		MachineType: prefix + "/zones/" + zoneID + "/machineTypes/" + machineType,
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    name,
					SourceImage: prefix + "/global/images/" + image,
				},
			},
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{
				{
					Key:   "ssh-keys",
					Value: "syzkaller:" + sshkey,
				},
				{
					Key:   "serial-port-enable",
					Value: "1",
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			&compute.NetworkInterface{
				Network: "global/networks/default",
			},
		},
		Scheduling: &compute.Scheduling{
			AutomaticRestart:  false,
			Preemptible:       false,
			OnHostMaintenance: "MIGRATE",
		},
	}

	<-apiRateGate
	op, err := computeService.Instances.Insert(projectID, zoneID, instance).Do()
	if err != nil {
		return "", fmt.Errorf("failed to create instance: %v", err)
	}
	if err := waitForCompletion("create", op.Name, false); err != nil {
		return "", err
	}

	<-apiRateGate
	inst, err := computeService.Instances.Get(projectID, zoneID, name).Do()
	if err != nil {
		return "", fmt.Errorf("error getting instance %s details after creation: %v", name, err)
	}

	// Finds its internal IP.
	ip := ""
	for _, iface := range inst.NetworkInterfaces {
		if strings.HasPrefix(iface.NetworkIP, "10.") {
			ip = iface.NetworkIP
			break
		}
	}
	if ip == "" {
		return "", fmt.Errorf("didn't find instance internal IP address")
	}
	return ip, nil
}

func deleteInstance(name string) error {
	<-apiRateGate
	op, err := computeService.Instances.Delete(projectID, zoneID, name).Do()
	apiErr, ok := err.(*googleapi.Error)
	if ok && apiErr.Code == 404 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete instance: %v", err)
	}
	if err := waitForCompletion("delete", op.Name, true); err != nil {
		return err
	}
	return nil
}

func waitForCompletion(desc, opName string, ignoreNotFound bool) error {
	for {
		time.Sleep(2 * time.Second)
		<-apiRateGate
		op, err := computeService.ZoneOperations.Get(projectID, zoneID, opName).Do()
		if err != nil {
			return fmt.Errorf("failed to get %v operation %v: %v", desc, opName, err)
		}
		switch op.Status {
		case "PENDING", "RUNNING":
			continue
		case "DONE":
			if op.Error != nil {
				reason := ""
				for _, operr := range op.Error.Errors {
					if ignoreNotFound && operr.Code == "RESOURCE_NOT_FOUND" {
						return nil
					}
					reason += fmt.Sprintf("%+v.", operr)
				}
				return fmt.Errorf("%v operation failed: %v", desc, reason)
			}
			return nil
		default:
			return fmt.Errorf("unknown %v operation status %q: %+v", desc, op.Status, op)
		}
	}
}

func sshArgs(sshKey, portArg string, port int) []string {
	return []string{
		portArg, fmt.Sprint(port),
		"-i", sshKey,
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=5",
	}
}
