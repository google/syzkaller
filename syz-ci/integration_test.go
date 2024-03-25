// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build integration
// +build integration

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/gcp"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
)

func TestSmokeWithTerratest(t *testing.T) {
	t.Parallel()
	projectID := gcp.GetGoogleProjectIDFromEnvVar(t)
	instanceName := fmt.Sprintf("terratest-syz-ci-smoke-%s", strings.ToLower(random.UniqueId()))

	// Retryable errors in terraform testing.
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./terratest",
		Vars: map[string]interface{}{
			"instance_name": instanceName,
		},
		EnvVars: map[string]string{
			"GOOGLE_CLOUD_PROJECT": projectID,
		},
	})
	defer terraform.Destroy(t, terraformOptions)

	terraform.InitAndApply(t, terraformOptions)
}
