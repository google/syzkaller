// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gce provides wrappers around Google Compute Engine (GCE) APIs.
// It is assumed that the program itself also runs on GCE as APIs operate on the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, API reference:
// https://cloud.google.com/compute/docs/reference/latest
// and Go API wrappers:
// https://godoc.org/google.golang.org/api/compute/v0.beta
package gce

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v0.beta"
	"google.golang.org/api/googleapi"
)

type Context struct {
	ProjectID  string
	ZoneID     string
	Instance   string
	InternalIP string
	ExternalIP string
	Network    string
	Subnetwork string

	computeService *compute.Service

	// apiCallTicker ticks regularly, preventing us from accidentally making
	// GCE API calls too quickly. Our quota is 20 QPS, but we limit ourselves
	// to less than that because several independent programs can do API calls.
	apiRateGate <-chan time.Time
}

func NewContext() (*Context, error) {
	ctx := &Context{
		apiRateGate: time.NewTicker(time.Second).C,
	}
	background := context.Background()
	tokenSource, err := google.DefaultTokenSource(background, compute.CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get a token source: %v", err)
	}
	httpClient := oauth2.NewClient(background, tokenSource)
	ctx.computeService, _ = compute.New(httpClient)
	// Obtain project name, zone and current instance IP address.
	ctx.ProjectID, err = ctx.getMeta("project/project-id")
	if err != nil {
		return nil, fmt.Errorf("failed to query gce project-id: %v", err)
	}
	ctx.ZoneID, err = ctx.getMeta("instance/zone")
	if err != nil {
		return nil, fmt.Errorf("failed to query gce zone: %v", err)
	}
	if i := strings.LastIndexByte(ctx.ZoneID, '/'); i != -1 {
		ctx.ZoneID = ctx.ZoneID[i+1:] // the query returns some nonsense prefix
	}
	ctx.Instance, err = ctx.getMeta("instance/name")
	if err != nil {
		return nil, fmt.Errorf("failed to query gce instance name: %v", err)
	}
	inst, err := ctx.computeService.Instances.Get(ctx.ProjectID, ctx.ZoneID, ctx.Instance).Do()
	if err != nil {
		return nil, fmt.Errorf("error getting instance info: %v", err)
	}
	for _, iface := range inst.NetworkInterfaces {
		if strings.HasPrefix(iface.NetworkIP, "10.") {
			ctx.InternalIP = iface.NetworkIP
		}
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				ctx.ExternalIP = ac.NatIP
			}
		}
		ctx.Network = iface.Network
		ctx.Subnetwork = iface.Subnetwork
	}
	if ctx.InternalIP == "" {
		return nil, fmt.Errorf("failed to get current instance internal IP")
	}
	return ctx, nil
}

func (ctx *Context) CreateInstance(name, machineType, image, sshkey string, preemptible bool) (string, error) {
	prefix := "https://www.googleapis.com/compute/v1/projects/" + ctx.ProjectID
	sshkeyAttr := "syzkaller:" + sshkey
	oneAttr := "1"
	falseAttr := false
	instance := &compute.Instance{
		Name:        name,
		Description: "syzkaller worker",
		MachineType: prefix + "/zones/" + ctx.ZoneID + "/machineTypes/" + machineType,
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
					Value: &sshkeyAttr,
				},
				{
					Key:   "serial-port-enable",
					Value: &oneAttr,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				Network:    ctx.Network,
				Subnetwork: ctx.Subnetwork,
			},
		},
		Scheduling: &compute.Scheduling{
			AutomaticRestart:  &falseAttr,
			Preemptible:       preemptible,
			OnHostMaintenance: "TERMINATE",
		},
	}

retry:
	if !instance.Scheduling.Preemptible && strings.HasPrefix(machineType, "e2-") {
		// Otherwise we get "Error 400: Efficient instances do not support
		// onHostMaintenance=TERMINATE unless they are preemptible".
		instance.Scheduling.OnHostMaintenance = "MIGRATE"
	}
	var op *compute.Operation
	err := ctx.apiCall(func() (err error) {
		op, err = ctx.computeService.Instances.Insert(ctx.ProjectID, ctx.ZoneID, instance).Do()
		return
	})
	if err != nil {
		return "", fmt.Errorf("failed to create instance: %v", err)
	}
	if err := ctx.waitForCompletion("zone", "create image", op.Name, false); err != nil {
		if _, ok := err.(resourcePoolExhaustedError); ok && instance.Scheduling.Preemptible {
			instance.Scheduling.Preemptible = false
			goto retry
		}
		return "", err
	}

	var inst *compute.Instance
	err = ctx.apiCall(func() (err error) {
		inst, err = ctx.computeService.Instances.Get(ctx.ProjectID, ctx.ZoneID, name).Do()
		return
	})
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

func (ctx *Context) DeleteInstance(name string, wait bool) error {
	var op *compute.Operation
	err := ctx.apiCall(func() (err error) {
		op, err = ctx.computeService.Instances.Delete(ctx.ProjectID, ctx.ZoneID, name).Do()
		return
	})
	if apiErr, ok := err.(*googleapi.Error); ok && apiErr.Code == 404 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete instance: %v", err)
	}
	if wait {
		if err := ctx.waitForCompletion("zone", "delete image", op.Name, true); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *Context) IsInstanceRunning(name string) bool {
	var inst *compute.Instance
	err := ctx.apiCall(func() (err error) {
		inst, err = ctx.computeService.Instances.Get(ctx.ProjectID, ctx.ZoneID, name).Do()
		return
	})
	if err != nil {
		return false
	}
	return inst.Status == "RUNNING"
}

func (ctx *Context) CreateImage(imageName, gcsFile string) error {
	image := &compute.Image{
		Name: imageName,
		RawDisk: &compute.ImageRawDisk{
			Source: "https://storage.googleapis.com/" + gcsFile,
		},
		Licenses: []string{
			"https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx",
		},
	}
	var op *compute.Operation
	err := ctx.apiCall(func() (err error) {
		op, err = ctx.computeService.Images.Insert(ctx.ProjectID, image).Do()
		return
	})
	if err != nil {
		// Try again without the vmx license in case it is not supported.
		image.Licenses = nil
		err := ctx.apiCall(func() (err error) {
			op, err = ctx.computeService.Images.Insert(ctx.ProjectID, image).Do()
			return
		})
		if err != nil {
			return fmt.Errorf("failed to create image: %v", err)
		}
	}
	if err := ctx.waitForCompletion("global", "create image", op.Name, false); err != nil {
		return err
	}
	return nil
}

func (ctx *Context) DeleteImage(imageName string) error {
	var op *compute.Operation
	err := ctx.apiCall(func() (err error) {
		op, err = ctx.computeService.Images.Delete(ctx.ProjectID, imageName).Do()
		return
	})
	if apiErr, ok := err.(*googleapi.Error); ok && apiErr.Code == 404 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete image: %v", err)
	}
	if err := ctx.waitForCompletion("global", "delete image", op.Name, true); err != nil {
		return err
	}
	return nil
}

type resourcePoolExhaustedError string

func (err resourcePoolExhaustedError) Error() string {
	return string(err)
}

func (ctx *Context) waitForCompletion(typ, desc, opName string, ignoreNotFound bool) error {
	time.Sleep(3 * time.Second)
	for {
		time.Sleep(3 * time.Second)
		var op *compute.Operation
		err := ctx.apiCall(func() (err error) {
			switch typ {
			case "global":
				op, err = ctx.computeService.GlobalOperations.Get(ctx.ProjectID, opName).Do()
			case "zone":
				op, err = ctx.computeService.ZoneOperations.Get(ctx.ProjectID, ctx.ZoneID, opName).Do()
			default:
				panic("unknown operation type: " + typ)
			}
			return
		})
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
					if operr.Code == "ZONE_RESOURCE_POOL_EXHAUSTED" {
						return resourcePoolExhaustedError(fmt.Sprintf("%+v", operr))
					}
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

func (ctx *Context) getMeta(path string) (string, error) {
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

func (ctx *Context) apiCall(fn func() error) error {
	rateLimited := 0
	for {
		<-ctx.apiRateGate
		err := fn()
		if err != nil {
			if strings.Contains(err.Error(), "Rate Limit Exceeded") ||
				strings.Contains(err.Error(), "rateLimitExceeded") {
				rateLimited++
				backoff := time.Duration(float64(rateLimited) * 1e9 * (rand.Float64() + 1))
				time.Sleep(backoff)
				if rateLimited < 20 {
					continue
				}
			}
		}
		return err
	}
}
