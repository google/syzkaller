// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"

	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
)

const exportTimeoutSeconds = 60 * 60 * 6

func handleBatchReproExport(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	for ns, nsConfig := range getConfig(ctx).Namespaces {
		if nsConfig.ReproExportPath == "" {
			continue
		}
		if err := createScriptJob(ctx, "syzkaller", "export-repro",
			exportReproScript(ns, nsConfig.ReproExportPath), exportTimeoutSeconds, nil); err != nil {
			log.Errorf(ctx, "createScriptJob: %s", err.Error())
		}
	}
}

func exportReproScript(srcNamespace, archivePath string) string {
	return "\n" +
		"git clone --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"./tools/syz-env \"" +
		"go run ./tools/syz-reprolist/... -namespace " + srcNamespace + " && " +
		"tar -czvf reproducers.tar.gz ./repros/ && " +
		"gsutil -m cp reproducers.tar.gz " + archivePath +
		"\""
}
