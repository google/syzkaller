// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-reporter creates table information from crashes.
// Useful tool together with tools/syz-crush to collect
// results from the reproducer runs.
//
// Nice extension to this would be to accept multiple configurations and
// then collect table from all the different workdirectories. This would allow easy comparison
// if different kernel version have same BUGs.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
)

type UISummaryData struct {
	Name                  string
	Crashes               []*UICrashType
	CrashCount            int
	CrashCountReproducers int
	Workdir               string
}

type UICrashType struct {
	Description    string
	ID             string
	Count          int
	Reproducers    map[string]string
	Crashes        []*UICrash
	CausingCommits []string
	FixingCommits  []string
	CausingConfigs []string
}

type UICrash struct {
	Index  int
	Log    string
	Report string
}

func main() {
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fn, err := osutil.TempFile("syz-reporter")
	if err != nil {
		log.Fatalf("%v", err)
	}
	fn += ".html"

	buf := new(bytes.Buffer)
	if httpSummary(buf, cfg) != nil {
		log.Fatalf("%v", err)
	}

	if err := osutil.WriteFile(fn, buf.Bytes()); err != nil {
		log.Fatalf("%v", err)
	}
	if err := exec.Command("xdg-open", fn).Start(); err != nil {
		log.Fatalf("failed to start browser: %v", err)
	}
}

func httpSummary(w io.Writer, cfg *mgrconfig.Config) error {
	data := &UISummaryData{
		Name:    cfg.Name,
		Workdir: cfg.Workdir,
	}

	var err error
	if data.Crashes, err = collectCrashes(cfg.Workdir); err != nil {
		return fmt.Errorf("failed to collect crashes: %v", err)
	}

	data.CrashCount = len(data.Crashes)

	for _, crash := range data.Crashes {
		if len(crash.Reproducers) > 0 {
			data.CrashCountReproducers = data.CrashCountReproducers + 1
		}
	}

	if err = summaryTemplate.Execute(w, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	return err
}

func collectCrashes(workdir string) ([]*UICrashType, error) {
	crashdir := filepath.Join(workdir, "crashes")
	dirs, err := osutil.ListDir(crashdir)
	if err != nil {
		return nil, err
	}
	var crashTypes []*UICrashType
	for _, dir := range dirs {
		crash := readCrash(workdir, dir)
		if crash != nil {
			crashTypes = append(crashTypes, crash)
		}
	}
	sort.Slice(crashTypes, func(i, j int) bool {
		return strings.ToLower(crashTypes[i].Description) < strings.ToLower(crashTypes[j].Description)
	})
	return crashTypes, nil
}

func readCrash(workdir, dir string) *UICrashType {
	if len(dir) != 40 {
		return nil
	}
	crashdir := filepath.Join(workdir, "crashes")
	descFile, err := os.Open(filepath.Join(crashdir, dir, "description"))
	if err != nil {
		return nil
	}
	defer descFile.Close()
	descBytes, err := ioutil.ReadAll(descFile)
	if err != nil || len(descBytes) == 0 {
		return nil
	}
	desc := string(trimNewLines(descBytes))
	descFile.Close()

	files, err := osutil.ListDir(filepath.Join(crashdir, dir))
	if err != nil {
		return nil
	}
	var crashes []*UICrash

	reproducers := make(map[string]string)
	var causingCommits []string
	var fixingCommits []string
	var causingConfigs []string
	for _, f := range files {
		if strings.HasPrefix(f, "log") {
			index, err := strconv.ParseUint(f[3:], 10, 64)
			if err == nil {
				crashes = append(crashes, &UICrash{
					Index: int(index),
				})
			}
		}

		if strings.HasPrefix(f, "tag") {
			tag, err := ioutil.ReadFile(filepath.Join(crashdir, dir, f))
			if err == nil {
				reproducers[string(tag)] = string(tag)
			}
		}

		if strings.HasSuffix(f, "prog") {
			reproducers[f] = f
		}

		if f == "cause.commit" {
			commits, err := ioutil.ReadFile(filepath.Join(crashdir, dir, f))
			if err == nil {
				causingCommits = strings.Split(string(commits), "\n")
			}
		}
		if f == "fix.commit" {
			commits, err := ioutil.ReadFile(filepath.Join(crashdir, dir, f))
			if err == nil {
				fixingCommits = strings.Split(string(commits), "\n")
			}
		}
		if f == kconfig.CauseConfigFile {
			configs, err := ioutil.ReadFile(filepath.Join(crashdir, dir, f))
			if err == nil {
				configsList := strings.Split(string(configs), "\n")
				// Ignore configuration list longer than 10
				if len(configsList) <= 10 {
					causingConfigs = configsList
				} else {
					causingConfigs = []string{"..."}
				}
			}
		}
	}

	return &UICrashType{
		Description:    desc,
		ID:             dir,
		Count:          len(crashes),
		Reproducers:    reproducers,
		Crashes:        crashes,
		CausingCommits: causingCommits,
		FixingCommits:  fixingCommits,
		CausingConfigs: causingConfigs,
	}
}

func trimNewLines(data []byte) []byte {
	for len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	return data
}

var summaryTemplate = html.CreatePage(`
<!doctype html>
<html>
<head>
	<title>{{.Name }} syzkaller</title>
	{{HEAD}}
</head>
<body>
<b>{{.Name }} syzkaller</b>
<br>
<b>Workdir: {{.Workdir }}</b>
<br>
<b>Crash Count: {{ .CrashCount }}</b>
<br>
<b>Crash With Reproducers Count: {{ .CrashCountReproducers }}</b>
<br>

<table class="list_table">
	<caption>Crashes:</caption>
	<tr>
		<th><a onclick="return sortTable(this, 'Description', textSort)" href="#">Description</a></th>
		<th><a onclick="return sortTable(this, 'Count', numSort)" href="#">Count</a></th>
		<th><a onclick="return sortTable(this, 'Reproducers', lineSort)" href="#">Reproducers</a></th>
		<th><a onclick="return sortTable(this, 'Causing_Commits', lineSort)" href="#">Causing_Commits</a></th>
		<th><a onclick="return sortTable(this, 'Fixing_Commits', lineSort)" href="#">Fixing_Commits</a></th>
		<th><a onclick="return sortTable(this, 'Causing_Configs', lineSort)" href="#">Causing_Configs</a></th>
	</tr>
	{{range $c := $.Crashes}}
	<tr>
		<td class="title">{{$c.Description}}</td>
		<td class="stat">{{$c.Count}}</td>
		<td class="reproducer">
		{{range $reproducer := $c.Reproducers}}
		{{$reproducer}}</br>
		{{end}}
		</td>
		<td class="Causing Commits">
		{{range $commit := $c.CausingCommits}}
		{{$commit}}</br>
		{{end}}
		</td>
		<td class="Fixing Commits">
		{{range $commit := $c.FixingCommits}}
		{{$commit}}</br>
		{{end}}
		</td>
		<td class="Causing Configs">
		{{range $config := $c.CausingConfigs}}
		{{$config}}</br>
		{{end}}
		</td>
	</tr>
	{{end}}
</table>

</body></html>
`)
