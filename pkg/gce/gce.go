// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gce provides wrappers around Google Compute Engine (GCE) APIs.
// It is assumed that the program itself also runs on GCE as APIs operate on the current project/zone.
//
// See https://cloud.google.com/compute/docs for details.
// In particular, API reference:
// https://cloud.google.com/compute/docs/reference/latest
// and Go API wrappers:
// https://godoc.org/google.golang.org/api/compute/v1
package gce

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/sys/targets"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

type Context struct {
	ProjectID  string
	ZoneID     string
	RegionID   string
	Instance   string
	InternalIP string
	ExternalIP string
	Network    string
	Subnetwork string

	computeService *compute.Service
	metadataServer string

	// apiCallTicker ticks regularly, preventing us from accidentally making
	// GCE API calls too quickly. Our quota is 20 QPS, but we limit ourselves
	// to less than that because several independent programs can do API calls.
	apiRateGate <-chan time.Time
}

type CreateArgs struct {
	Preemptible   bool
	DisplayDevice bool
}

type InstanceConfig struct {
	Name                 string
	MachineType          string
	Image                string
	SSHKey               string
	Tags                 []string
	Preemptible          bool
	DisplayDevice        bool
	NestedVirtualization bool
	NicType              string
	VMRunningTime        time.Duration
}

var metadataURL = "http://metadata.google.internal/computeMetadata/v1/"

func NewContext(customZoneID, customProjectID string) (*Context, error) {
	ctx := &Context{
		apiRateGate:    time.NewTicker(time.Second).C,
		metadataServer: metadataURL,
	}
	background := context.Background()
	tokenSource, err := google.DefaultTokenSource(background, compute.CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get a token source: %w", err)
	}
	httpClient := oauth2.NewClient(background, tokenSource)
	ctx.computeService, err = compute.NewService(background, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to create compute service: %w", err)
	}
	// Obtain project name, zone and current instance IP address.
	instanceProject, err := ctx.getMeta("project/project-id")
	if err != nil {
		return nil, fmt.Errorf("failed to query gce project-id: %w", err)
	}
	if customProjectID != "" {
		ctx.ProjectID = customProjectID
	} else {
		ctx.ProjectID = instanceProject
	}
	instanceZone, err := ctx.localZone()
	if err != nil {
		return nil, fmt.Errorf("failed to get local zone: %w", err)
	}
	if customZoneID != "" {
		ctx.ZoneID = customZoneID
	} else {
		ctx.ZoneID = instanceZone
	}
	if !validateZone(ctx.ZoneID) {
		return nil, fmt.Errorf("%q is not a valid zone name", ctx.ZoneID)
	}
	ctx.RegionID = zoneToRegion(ctx.ZoneID)
	if ctx.RegionID == "" {
		return nil, fmt.Errorf("failed to extract region id from %s", ctx.ZoneID)
	}
	ctx.Instance, err = ctx.getMeta("instance/name")
	if err != nil {
		return nil, fmt.Errorf("failed to query gce instance name: %w", err)
	}
	inst, err := ctx.computeService.Instances.Get(instanceProject, instanceZone, ctx.Instance).Do()
	if err != nil {
		return nil, fmt.Errorf("error getting instance info: %w", err)
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

func (ctx *Context) CreateInstance(cfg *InstanceConfig) (string, error) {
	prefix := "https://www.googleapis.com/compute/v1/projects/" + ctx.ProjectID
	sshkeyAttr := "syzkaller:" + cfg.SSHKey
	oneAttr := "1"
	falseAttr := false
	instance := &compute.Instance{
		Name:        cfg.Name,
		Description: "syzkaller worker",
		MachineType: prefix + "/zones/" + ctx.ZoneID + "/machineTypes/" + cfg.MachineType,
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				DiskSizeGb: int64(diskSizeGB(cfg.MachineType)),
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    cfg.Name,
					SourceImage: prefix + "/global/images/" + cfg.Image,
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
				NicType:    cfg.NicType,
			},
		},
		Scheduling: &compute.Scheduling{
			AutomaticRestart:  &falseAttr,
			Preemptible:       cfg.Preemptible,
			OnHostMaintenance: "TERMINATE",
		},
		DisplayDevice: &compute.DisplayDevice{
			EnableDisplay: cfg.DisplayDevice,
		},
		AdvancedMachineFeatures: &compute.AdvancedMachineFeatures{
			EnableNestedVirtualization: cfg.NestedVirtualization,
		},
	}
	if cfg.VMRunningTime != 0 {
		instance.Scheduling.MaxRunDuration = &compute.Duration{
			// Give the manager an extra hour to ensure it has time to do its own cleanup.
			Seconds: int64((cfg.VMRunningTime + time.Hour) / time.Second),
		}
		instance.Scheduling.InstanceTerminationAction = "DELETE"
	}
	if instance.Scheduling.Preemptible {
		instance.Scheduling.ProvisioningModel = "SPOT"
	}
retry:
	if !instance.Scheduling.Preemptible && strings.HasPrefix(cfg.MachineType, "e2-") {
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
		return "", fmt.Errorf("failed to create instance: %w", err)
	}
	if err := ctx.waitForZonalCompletion("create instance", op.Name, false); err != nil {
		var resourcePoolExhaustedError resourcePoolExhaustedError
		if errors.As(err, &resourcePoolExhaustedError) && instance.Scheduling.Preemptible {
			instance.Scheduling.Preemptible = false
			instance.Scheduling.ProvisioningModel = "STANDARD"
			goto retry
		}
		return "", err
	}

	var inst *compute.Instance
	err = ctx.apiCall(func() (err error) {
		inst, err = ctx.computeService.Instances.Get(ctx.ProjectID, ctx.ZoneID, cfg.Name).Do()
		return
	})
	if err != nil {
		return "", fmt.Errorf("error getting instance %s details after creation: %w", cfg.Name, err)
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

func diskSizeGB(machineType string) int {
	if strings.HasPrefix(machineType, "c4a-") {
		// For C4A machines, the only available disk type is "Hyperdisk Balanced",
		// which must be >= 10GB.
		return 10
	}
	// Use the default value.
	return 0
}

func (ctx *Context) DeleteInstance(name string, wait bool) error {
	var op *compute.Operation
	err := ctx.apiCall(func() (err error) {
		op, err = ctx.computeService.Instances.Delete(ctx.ProjectID, ctx.ZoneID, name).Do()
		return
	})
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == 404 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete instance: %w", err)
	}
	if wait {
		if err := ctx.waitForZonalCompletion("delete instance", op.Name, true); err != nil {
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

func (ctx *Context) CreateImage(imageName, gcsFile, OS string) error {
	var features []*compute.GuestOsFeature
	if OS == targets.Linux {
		features = []*compute.GuestOsFeature{
			{
				Type: "GVNIC",
			},
		}
	}
	image := &compute.Image{
		Name: imageName,
		RawDisk: &compute.ImageRawDisk{
			Source: "https://storage.googleapis.com/" + gcsFile,
		},
		Licenses: []string{
			"https://www.googleapis.com/compute/v1/projects/vm-options/global/licenses/enable-vmx",
		},
		GuestOsFeatures: features,
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
			return fmt.Errorf("failed to create image: %w", err)
		}
	}
	if err := ctx.waitForGlobalCompletion("create image", op.Name, false); err != nil {
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
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == 404 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete image: %w", err)
	}
	if err := ctx.waitForGlobalCompletion("delete image", op.Name, true); err != nil {
		return err
	}
	return nil
}

type resourcePoolExhaustedError string

func (err resourcePoolExhaustedError) Error() string {
	return string(err)
}

func (ctx *Context) waitForZonalCompletion(desc, opName string, ignoreNotFound bool) error {
	return ctx.waitForCompletion("zone", desc, opName, ignoreNotFound)
}

func (ctx *Context) waitForGlobalCompletion(desc, opName string, ignoreNotFound bool) error {
	return ctx.waitForCompletion("global", desc, opName, ignoreNotFound)
}

func (ctx *Context) waitForCompletion(typ, desc, opName string, ignoreNotFound bool) error {
	for {
		time.Sleep(3 * time.Second)
		var op *compute.Operation
		err := ctx.apiCall(func() (err error) {
			switch typ {
			case "global":
				op, err = ctx.computeService.GlobalOperations.Wait(ctx.ProjectID, opName).Do()
			case "zone":
				op, err = ctx.computeService.ZoneOperations.Wait(ctx.ProjectID, ctx.ZoneID, opName).Do()
			default:
				panic("unknown operation type: " + typ)
			}
			return
		})
		if err != nil {
			return fmt.Errorf("failed to get %v operation %v: %w", desc, opName, err)
		}
		switch op.Status {
		case "PENDING", "RUNNING":
			continue
		case "DONE":
			if op.Error != nil {
				reason := ""
				for _, operr := range op.Error.Errors {
					if operr.Code == "ZONE_RESOURCE_POOL_EXHAUSTED" ||
						operr.Code == "ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS" {
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
	req, err := http.NewRequest("GET", ctx.metadataServer+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// localZone returns the local zone of the machine. The GCE metadata API
// returns a fully qualified resource name, like "projects/1234/zones/us-central1-c",
// so we drop the prefix to return just the zone ID.
func (ctx *Context) localZone() (string, error) {
	zone, err := ctx.getMeta("instance/zone")
	if err != nil {
		return "", err
	}
	if i := strings.LastIndexByte(zone, '/'); i != -1 {
		zone = zone[i+1:]
	}
	return zone, nil
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

var zoneNameRe = regexp.MustCompile("^[a-zA-Z0-9]*-[a-zA-Z0-9]*[-][a-zA-Z0-9]*$")

func validateZone(zone string) bool {
	return zoneNameRe.MatchString(zone)
}

var regionNameRe = regexp.MustCompile("^[a-zA-Z0-9]*-[a-zA-Z0-9]*")

func zoneToRegion(zone string) string {
	return regionNameRe.FindString(zone)
}
