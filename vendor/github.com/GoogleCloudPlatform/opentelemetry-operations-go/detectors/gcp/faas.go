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
	"strings"
)

const (
	// See the Cloud Run env vars:
	// https://cloud.google.com/run/docs/reference/container-contract
	// and the Cloud Functions env vars:
	// https://cloud.google.com/functions/docs/configuring/env-var#runtime_environment_variables_set_automatically
	cloudRunConfigEnv      = "K_CONFIGURATION"
	cloudFunctionTargetEnv = "FUNCTION_TARGET"
	faasServiceEnv         = "K_SERVICE"
	faasRevisionEnv        = "K_REVISION"
	regionMetadataAttr     = "instance/region"
)

func (d *Detector) onCloudRun() bool {
	_, found := d.os.LookupEnv(cloudRunConfigEnv)
	return found
}

func (d *Detector) onCloudFunctions() bool {
	_, found := d.os.LookupEnv(cloudFunctionTargetEnv)
	return found
}

// FaaSName returns the name of the cloud run or cloud functions service.
func (d *Detector) FaaSName() (string, error) {
	if name, found := d.os.LookupEnv(faasServiceEnv); found {
		return name, nil
	}
	return "", errEnvVarNotFound
}

// FaaSVersion returns the revision of the cloud run or cloud functions service.
func (d *Detector) FaaSVersion() (string, error) {
	if version, found := d.os.LookupEnv(faasRevisionEnv); found {
		return version, nil
	}
	return "", errEnvVarNotFound
}

// FaaSID returns the instance id of the cloud run instance or cloud function.
func (d *Detector) FaaSID() (string, error) {
	return d.metadata.InstanceID()
}

// FaaSCloudRegion detects region from the metadata server.  It is in the
// format /projects/<project_number>/regions/<region>.
// https://cloud.google.com/run/docs/reference/container-contract#metadata-server
func (d *Detector) FaaSCloudRegion() (string, error) {
	region, err := d.metadata.Get(regionMetadataAttr)
	if err != nil {
		return "", err
	}
	return region[strings.LastIndex(region, "/")+1:], nil
}
