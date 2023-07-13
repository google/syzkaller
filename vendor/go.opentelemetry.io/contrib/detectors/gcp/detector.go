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

	"cloud.google.com/go/compute/metadata"
	"github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// NewDetector returns a resource detector which detects resource attributes on:
// * Google Compute Engine (GCE).
// * Google Kubernetes Engine (GKE).
// * Google App Engine (GAE).
// * Cloud Run.
// * Cloud Functions.
func NewDetector() resource.Detector {
	return &detector{detector: gcp.NewDetector()}
}

type detector struct {
	detector gcpDetector
}

// Detect detects associated resources when running on GCE, GKE, GAE,
// Cloud Run, and Cloud functions.
func (d *detector) Detect(ctx context.Context) (*resource.Resource, error) {
	if !metadata.OnGCE() {
		return nil, nil
	}
	b := &resourceBuilder{}
	b.attrs = append(b.attrs, semconv.CloudProviderGCP)
	b.add(semconv.CloudAccountIDKey, d.detector.ProjectID)

	switch d.detector.CloudPlatform() {
	case gcp.GKE:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPKubernetesEngine)
		b.addZoneOrRegion(d.detector.GKEAvailabilityZoneOrRegion)
		b.add(semconv.K8SClusterNameKey, d.detector.GKEClusterName)
		b.add(semconv.HostIDKey, d.detector.GKEHostID)
	case gcp.CloudRun:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPCloudRun)
		b.add(semconv.FaaSNameKey, d.detector.FaaSName)
		b.add(semconv.FaaSVersionKey, d.detector.FaaSVersion)
		b.add(semconv.FaaSIDKey, d.detector.FaaSID)
		b.add(semconv.CloudRegionKey, d.detector.FaaSCloudRegion)
	case gcp.CloudFunctions:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPCloudFunctions)
		b.add(semconv.FaaSNameKey, d.detector.FaaSName)
		b.add(semconv.FaaSVersionKey, d.detector.FaaSVersion)
		b.add(semconv.FaaSIDKey, d.detector.FaaSID)
		b.add(semconv.CloudRegionKey, d.detector.FaaSCloudRegion)
	case gcp.AppEngineFlex:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPAppEngine)
		b.addZoneAndRegion(d.detector.AppEngineFlexAvailabilityZoneAndRegion)
		b.add(semconv.FaaSNameKey, d.detector.AppEngineServiceName)
		b.add(semconv.FaaSVersionKey, d.detector.AppEngineServiceVersion)
		b.add(semconv.FaaSIDKey, d.detector.AppEngineServiceInstance)
	case gcp.AppEngineStandard:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPAppEngine)
		b.add(semconv.CloudAvailabilityZoneKey, d.detector.AppEngineStandardAvailabilityZone)
		b.add(semconv.CloudRegionKey, d.detector.AppEngineStandardCloudRegion)
		b.add(semconv.FaaSNameKey, d.detector.AppEngineServiceName)
		b.add(semconv.FaaSVersionKey, d.detector.AppEngineServiceVersion)
		b.add(semconv.FaaSIDKey, d.detector.AppEngineServiceInstance)
	case gcp.GCE:
		b.attrs = append(b.attrs, semconv.CloudPlatformGCPComputeEngine)
		b.addZoneAndRegion(d.detector.GCEAvailabilityZoneAndRegion)
		b.add(semconv.HostTypeKey, d.detector.GCEHostType)
		b.add(semconv.HostIDKey, d.detector.GCEHostID)
		b.add(semconv.HostNameKey, d.detector.GCEHostName)
	default:
		// We don't support this platform yet, so just return with what we have
	}
	return b.build()
}

// resourceBuilder simplifies constructing resources using GCP detection
// library functions.
type resourceBuilder struct {
	errs  []error
	attrs []attribute.KeyValue
}

func (r *resourceBuilder) add(key attribute.Key, detect func() (string, error)) {
	if v, err := detect(); err == nil {
		r.attrs = append(r.attrs, key.String(v))
	} else {
		r.errs = append(r.errs, err)
	}
}

// zoneAndRegion functions are expected to return zone, region, err.
func (r *resourceBuilder) addZoneAndRegion(detect func() (string, string, error)) {
	if zone, region, err := detect(); err == nil {
		r.attrs = append(r.attrs, semconv.CloudAvailabilityZone(zone))
		r.attrs = append(r.attrs, semconv.CloudRegion(region))
	} else {
		r.errs = append(r.errs, err)
	}
}

func (r *resourceBuilder) addZoneOrRegion(detect func() (string, gcp.LocationType, error)) {
	if v, locType, err := detect(); err == nil {
		switch locType {
		case gcp.Zone:
			r.attrs = append(r.attrs, semconv.CloudAvailabilityZone(v))
		case gcp.Region:
			r.attrs = append(r.attrs, semconv.CloudRegion(v))
		default:
			r.errs = append(r.errs, fmt.Errorf("location must be zone or region. Got %v", locType))
		}
	} else {
		r.errs = append(r.errs, err)
	}
}

func (r *resourceBuilder) build() (*resource.Resource, error) {
	var err error
	if len(r.errs) > 0 {
		err = fmt.Errorf("%w: %s", resource.ErrPartialResource, r.errs)
	}
	return resource.NewWithAttributes(semconv.SchemaURL, r.attrs...), err
}
