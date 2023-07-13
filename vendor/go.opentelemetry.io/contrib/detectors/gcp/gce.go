// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcp // import "go.opentelemetry.io/contrib/detectors/gcp"

import (
	"context"
	"fmt"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// GCE collects resource information of GCE computing instances.
// Deprecated: Use gcp.NewDetector() instead, which sets the same resource attributes on GCE.
type GCE struct{}

// compile time assertion that GCE implements the resource.Detector interface.
var _ resource.Detector = (*GCE)(nil)

// Detect detects associated resources when running on GCE hosts.
func (gce *GCE) Detect(ctx context.Context) (*resource.Resource, error) {
	if !metadata.OnGCE() {
		return nil, nil
	}

	attributes := []attribute.KeyValue{
		semconv.CloudProviderGCP,
	}

	var errInfo []string

	if projectID, err := metadata.ProjectID(); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if projectID != "" {
		attributes = append(attributes, semconv.CloudAccountID(projectID))
	}

	if zone, err := metadata.Zone(); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if zone != "" {
		attributes = append(attributes, semconv.CloudAvailabilityZone(zone))

		splitArr := strings.SplitN(zone, "-", 3)
		if len(splitArr) == 3 {
			attributes = append(attributes, semconv.CloudRegion(strings.Join(splitArr[0:2], "-")))
		}
	}

	if instanceID, err := metadata.InstanceID(); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if instanceID != "" {
		attributes = append(attributes, semconv.HostID(instanceID))
	}

	if name, err := metadata.InstanceName(); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if name != "" {
		attributes = append(attributes, semconv.HostName(name))
	}

	if hostname, err := os.Hostname(); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if hostname != "" {
		attributes = append(attributes, semconv.HostName(hostname))
	}

	if hostType, err := metadata.Get("instance/machine-type"); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if hostType != "" {
		attributes = append(attributes, semconv.HostType(hostType))
	}

	var aggregatedErr error
	if len(errInfo) > 0 {
		aggregatedErr = fmt.Errorf("detecting GCE resources: %s", errInfo)
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), aggregatedErr
}

// hasProblem checks if the err is not nil or for missing resources.
func hasProblem(err error) bool {
	if err == nil {
		return false
	}
	if _, undefined := err.(metadata.NotDefinedError); undefined {
		return false
	}
	return true
}
