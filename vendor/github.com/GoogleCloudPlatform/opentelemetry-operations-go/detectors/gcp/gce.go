// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcp

import (
	"fmt"
	"strings"
)

// See the available GCE instance metadata:
// https://cloud.google.com/compute/docs/metadata/default-metadata-values#vm_instance_metadata
const machineTypeMetadataAttr = "instance/machine-type"

func (d *Detector) onGCE() bool {
	_, err := d.metadata.Get(machineTypeMetadataAttr)
	return err == nil
}

// GCEHostType returns the machine type of the instance on which this program is running.
func (d *Detector) GCEHostType() (string, error) {
	return d.metadata.Get(machineTypeMetadataAttr)
}

// GCEHostID returns the instance ID of the instance on which this program is running.
func (d *Detector) GCEHostID() (string, error) {
	return d.metadata.InstanceID()
}

// GCEHostName returns the instance name of the instance on which this program is running.
func (d *Detector) GCEHostName() (string, error) {
	return d.metadata.InstanceName()
}

// GCEAvailabilityZoneAndRegion returns the zone and region in which this program is running.
func (d *Detector) GCEAvailabilityZoneAndRegion() (string, string, error) {
	zone, err := d.metadata.Zone()
	if err != nil {
		return "", "", err
	}
	if zone == "" {
		return "", "", fmt.Errorf("no zone detected from GCE metadata server")
	}
	splitZone := strings.SplitN(zone, "-", 3)
	if len(splitZone) != 3 {
		return "", "", fmt.Errorf("zone was not in the expected format: country-region-zone.  Got %v", zone)
	}
	return zone, strings.Join(splitZone[0:2], "-"), nil
}
