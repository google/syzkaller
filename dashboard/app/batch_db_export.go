// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"

	"cloud.google.com/go/batch/apiv1/batchpb"
	"google.golang.org/appengine/v2/log"
)

const exportTimeoutSeconds = 60 * 60 * 6

func handleBatchDBExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		if nsConfig.ReproExportPath == "" {
			continue
		}
		serviceAccount := &batchpb.ServiceAccount{
			Scopes: []string{"https://www.googleapis.com/auth/userinfo.email"},
		}
		if err := createScriptJob(ctx, "syzkaller", "db-export",
			exportDBScript(ns, nsConfig.ReproExportPath), exportTimeoutSeconds, serviceAccount); err != nil {
			log.Errorf(ctx, "createScriptJob: %s", err.Error())
		}
	}
}

func exportDBScript(srcNamespace, archivePath string) string {
	return "\n" +
		"set -ue\n" +
		"echo \"Cloning syzkaller...\"\n" +
		"git clone -q --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"echo \"Getting auth token...\"\n" +
		"token=$(curl -sSf -H \"Metadata-Flavor: Google\" " +
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | " +
		"sed -n 's/.*\"access_token\":\"\\([^\"]*\\)\".*/\\1/p')\n" +
		"if [ -z \"$token\" ]; then echo \"WARNING: gcloud auth token is empty\"; fi\n" +
		"echo \"Running syz-db-export inside syz-env...\"\n" +
		"CI=1 ./tools/syz-env \"" + // CI=1 to suppress "The input device is not a TTY".
		"echo 'Building syz-db-export...' && " +
		"go build -o ./syz-db-export-bin ./tools/syz-db-export/... 2>&1 && " +
		"echo 'Starting export process...' && " +
		"./syz-db-export-bin -namespace " + srcNamespace + " -output export -token '$token' -j 10 && " +
		"echo 'Export finished. Creating tarball...' && " +
		"tar -czf export.tar.gz ./export/ && " +
		"echo 'Tarball created. Copying to GCS...' && " +
		"gcloud storage cp export.tar.gz " + archivePath + " 2>&1" +
		"\""
}
