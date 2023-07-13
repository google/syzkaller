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

	"cloud.google.com/go/compute/metadata"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// GKE collects resource information of GKE computing instances.
// Deprecated: Use gcp.NewDetector() instead, which does NOT detect container, pod, and namespace attributes.
// Set those using name using the OTEL_RESOURCE_ATTRIBUTES env var instead.
type GKE struct{}

// compile time assertion that GKE implements the resource.Detector interface.
var _ resource.Detector = (*GKE)(nil)

// Detect detects associated resources when running in GKE environment.
func (gke *GKE) Detect(ctx context.Context) (*resource.Resource, error) {
	gcpDetecor := GCE{}
	gceLablRes, err := gcpDetecor.Detect(ctx)

	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return gceLablRes, err
	}

	var errInfo []string
	if err != nil {
		errInfo = append(errInfo, err.Error())
	}

	attributes := []attribute.KeyValue{
		semconv.K8SNamespaceName(os.Getenv("NAMESPACE")),
		semconv.K8SPodName(os.Getenv("HOSTNAME")),
	}

	if containerName := os.Getenv("CONTAINER_NAME"); containerName != "" {
		attributes = append(attributes, semconv.ContainerName(containerName))
	}

	if clusterName, err := metadata.InstanceAttributeValue("cluster-name"); hasProblem(err) {
		errInfo = append(errInfo, err.Error())
	} else if clusterName != "" {
		attributes = append(attributes, semconv.K8SClusterName(clusterName))
	}

	k8sattributeRes := resource.NewWithAttributes(semconv.SchemaURL, attributes...)

	res, err := resource.Merge(gceLablRes, k8sattributeRes)
	if err != nil {
		errInfo = append(errInfo, err.Error())
	}

	var aggregatedErr error
	if len(errInfo) > 0 {
		aggregatedErr = fmt.Errorf("detecting GKE resources: %s", errInfo)
	}

	return res, aggregatedErr
}
