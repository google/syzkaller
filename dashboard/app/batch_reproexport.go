// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"

	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
)

const exportTimeoutSeconds = 10000 * 2 // upstream has apx 7k reproducers, 1s each max (throttling)

func handleBatchReproExport(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	reproExportPath := getConfig(ctx).ReproExportPath
	if reproExportPath == "" {
		return
	}
	if err := createScriptJob(ctx, "syzkaller", "export-repro",
		exportReproScript(reproExportPath),
		exportTimeoutSeconds, nil); err != nil {
		log.Errorf(ctx, "createScriptJob: %s", err.Error())
	}
}

func exportReproScript(archivePath string) string {
	script := "\n" +
		"git clone --depth 1 --branch master --single-branch https://github.com/google/syzkaller\n" +
		"cd syzkaller\n" +
		"export CI=1\n" +
		"./tools/syz-env \"" +
		"go run ./tools/syz-reprolist/... -namespace upstream; " +
		"tar -czvf reproducers.tar.gz ./repros/; " +
		"gsutil -m cp reproducers.tar.gz " + archivePath + ";" +
		"\""
	return script
}
