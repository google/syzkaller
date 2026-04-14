// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-aflow tool can be used to invoke any agentic workflow registered with pkg/aflow.
// See tools/syz-aflow/README.md for instructions.
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

	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	aflowhtml "github.com/google/syzkaller/pkg/aflow/trajectory/html"
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
		flagHTML = flag.String("html", "", "write execution trajectory into this local HTML file in real-time")
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
	if err := run(context.Background(), RunArgs{
		Model:     *flagModel,
		FlowName:  *flagFlow,
		InputFile: *flagInput,
		Workdir:   *flagWorkdir,
		HTMLFile:  *flagHTML,
		CacheSize: cacheSize,
	}); err != nil {
		tool.Failf("%v", osutil.VerboseMessage(err))
	}
}

type RunArgs struct {
	Model     string
	FlowName  string
	InputFile string
	Workdir   string
	HTMLFile  string
	CacheSize uint64
}

func run(ctx context.Context, args RunArgs) error {
	flow := aflow.Flows[args.FlowName]
	if flow == nil {
		return fmt.Errorf("workflow %q is not found", args.FlowName)
	}
	inputData, err := os.ReadFile(args.InputFile)
	if err != nil {
		return fmt.Errorf("failed to open -input file: %w", err)
	}
	var inputs map[string]any
	if err := json.Unmarshal(inputData, &inputs); err != nil {
		return err
	}
	cache, err := aflow.NewCache(filepath.Join(args.Workdir, "cache"), args.CacheSize)
	if err != nil {
		return err
	}

	var spans []*trajectory.Span
	spansMap := make(map[int]*trajectory.Span)
	onEventFunc := func(span *trajectory.Span) error {
		if _, ok := spansMap[span.Seq]; !ok {
			spans = append(spans, span)
		}
		spansMap[span.Seq] = span
		if args.HTMLFile != "" {
			f, err := os.Create(args.HTMLFile)
			if err != nil {
				log.Printf("failed to create HTML file: %v", err)
			} else {
				if err := aflowhtml.RenderReport(f, spans); err != nil {
					log.Printf("failed to render trajectory: %v", err)
				}
				f.Close()
			}
		}
		if span.Error != "" {
			return nil
		}
		log.Printf("%v", span)
		return nil
	}

	_, err = flow.Execute(ctx, args.Model, args.Workdir, inputs, cache, onEventFunc)
	return err
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

	inputs := map[string]any{
		"KernelRepo":   crash["kernel-source-git"],
		"KernelCommit": crash["kernel-source-commit"],
		"BugTitle":     crash["title"],
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
