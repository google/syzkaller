// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-aflow tool can be used to invoke any agentic workflow registered with pkg/aflow.
// For example, to run the patching workflow use:
//
//	go run ./tools/syz-aflow -input=input.json -download-bug=d8fd35fa6177afa8c92b
//	go run ./tools/syz-aflow -input=input.json -workflow=patching -workdir=workdir
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"

	"golang.org/x/oauth2/google"
)

func main() {
	var (
		flagFlow        = flag.String("workflow", "", "workflow to execute")
		flagInput       = flag.String("input", "", "input json file with workflow arguments")
		flagWorkdir     = flag.String("workdir", "", "directory for kernel checkout, kernel builds, etc")
		flagModel       = flag.String("model", "", "use this LLM model, if empty use default models")
		flagCacheSize   = flag.String("cache-size", "10GB", "max cache size (e.g. 100MB, 5GB, 1TB)")
		flagDownloadBug = flag.String("download-bug", "", "extid or id of a bug to download from the dashboard"+
			" and save into -input file")
		flagAuth = flag.Bool("auth", false, "use gcloud auth token for downloading bugs (set it up with"+
			" gcloud auth application-default login)")
	)
	defer tool.Init()()
	if *flagDownloadBug != "" {
		token := ""
		if *flagAuth {
			var err error
			token, err = getAccessToken()
			if err != nil {
				tool.Fail(err)
			}
		}
		if err := downloadBug(*flagDownloadBug, *flagInput, token); err != nil {
			tool.Fail(err)
		}
		return
	}
	if *flagFlow == "" {
		fmt.Fprintf(os.Stderr, "syz-aflow usage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "available workflows:\n")
		for _, flow := range aflow.Flows {
			fmt.Fprintf(os.Stderr, "\t%v: %v\n", flow.Name, flow.Description)
		}
		return
	}
	cacheSize, err := parseSize(*flagCacheSize)
	if err != nil {
		tool.Fail(err)
	}
	if err := run(context.Background(), *flagModel, *flagFlow, *flagInput, *flagWorkdir, cacheSize); err != nil {
		tool.Fail(err)
	}
}

func run(ctx context.Context, model, flowName, inputFile, workdir string, cacheSize uint64) error {
	flow := aflow.Flows[flowName]
	if flow == nil {
		return fmt.Errorf("workflow %q is not found", flowName)
	}
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open -input file: %w", err)
	}
	var inputs map[string]any
	if err := json.Unmarshal(inputData, &inputs); err != nil {
		return err
	}
	cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), cacheSize)
	if err != nil {
		return err
	}
	_, err = flow.Execute(ctx, model, workdir, inputs, cache, onEvent)
	return err
}

func onEvent(span *trajectory.Span) error {
	if span.Error != "" {
		// We do not want to print error twice (once here and once in main).
		// So we ignore those events.
		return nil
	}
	log.Printf("%v", span)
	return nil
}

func downloadBug(id, inputFile, token string) error {
	if inputFile == "" {
		return fmt.Errorf("-download-bug requires -input flag")
	}
	resp, err := get(fmt.Sprintf("/bug?extid=%v&json=1", id), token)
	if err != nil {
		// Retry with "id=" if we failed with "extid="
		resp, err = get(fmt.Sprintf("/bug?id=%v&json=1", id), token)
		if err != nil {
			return err
		}
	}
	var info map[string]any
	if err := json.Unmarshal([]byte(resp), &info); err != nil {
		return fmt.Errorf(
			"response for bug ID %v was not valid JSON: %w",
			id, err,
		)
	}
	crash := info["crashes"].([]any)[0].(map[string]any)

	repoURL, _ := crash["kernel-source-git"].(string)

	// Clean the URL to end at .git.
	if dotGitIndex := strings.Index(repoURL, ".git"); dotGitIndex != -1 {
		repoURL = repoURL[:dotGitIndex+4]
	}

	inputs := map[string]any{
		"SyzkallerCommit": crash["syzkaller-commit"],
		"KernelRepo":      repoURL,
		"KernelCommit":    crash["kernel-source-commit"],
	}

	fetchText := func(key string) (string, error) {
		path, ok := crash[key].(string)
		if !ok || path == "" {
			return "", nil
		}
		return get(path, token)
	}

	inputs["ReproSyz"], err = fetchText("syz-reproducer")
	if err != nil {
		return err
	}
	inputs["ReproC"], err = fetchText("c-reproducer")
	if err != nil {
		return err
	}
	inputs["KernelConfig"], err = fetchText("kernel-config")
	if err != nil {
		return err
	}
	inputs["CrashReport"], err = fetchText("crash-report-link")
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(inputs, "", "\t")
	if err != nil {
		return err
	}
	return osutil.WriteFile(inputFile, data)
}

func get(path, token string) (string, error) {
	if path == "" {
		return "", nil
	}
	const host = "https://syzbot.org"
	req, err := http.NewRequest("GET", fmt.Sprintf("%v%v", host, path), nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed: %v", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func getAccessToken() (string, error) {
	ctx := context.Background()
	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}
	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return "", err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("error retrieving token from source: %w", err)
	}

	return token.AccessToken, nil
}

func parseSize(s string) (uint64, error) {
	var size uint64
	var suffix string
	if _, err := fmt.Sscanf(s, "%d%s", &size, &suffix); err != nil {
		return 0, fmt.Errorf("failed to parse cache size %q: %w", s, err)
	}
	switch suffix {
	case "KB":
		size <<= 10
	case "MB":
		size <<= 20
	case "GB":
		size <<= 30
	case "TB":
		size <<= 40
	case "":
	default:
		return 0, fmt.Errorf("unknown size suffix %q", suffix)
	}
	return size, nil
}
