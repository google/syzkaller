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
	"os"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

const (
	gcpFunctionNameKey = "K_SERVICE"
)

// NewCloudFunction will return a GCP Cloud Function resource detector.
// Deprecated: Use gcp.NewDetector() instead, which sets the same resource attributes.
func NewCloudFunction() resource.Detector {
	return &cloudFunction{
		cloudRun: NewCloudRun(),
	}
}

// cloudFunction collects resource information of GCP Cloud Function.
type cloudFunction struct {
	cloudRun *CloudRun
}

// Detect detects associated resources when running in GCP Cloud Function.
func (f *cloudFunction) Detect(ctx context.Context) (*resource.Resource, error) {
	functionName, ok := f.googleCloudFunctionName()
	if !ok {
		return nil, nil
	}

	projectID, err := f.cloudRun.mc.ProjectID()
	if err != nil {
		return nil, err
	}
	region, err := f.cloudRun.cloudRegion(ctx)
	if err != nil {
		return nil, err
	}

	attributes := []attribute.KeyValue{
		semconv.CloudProviderGCP,
		semconv.CloudPlatformGCPCloudFunctions,
		semconv.FaaSName(functionName),
		semconv.CloudAccountID(projectID),
		semconv.CloudRegion(region),
	}
	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), nil
}

func (f *cloudFunction) googleCloudFunctionName() (string, bool) {
	return os.LookupEnv(gcpFunctionNameKey)
}
