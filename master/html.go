// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
)

func (m *Master) httpInfo(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data := &UIData{
		CorpusLen: len(m.corpus.m),
	}
	for _, mgr := range m.managers {
		data.Managers = append(data.Managers, UIManager{
			Name: mgr.name,
			Http: mgr.http,
		})
	}
	if err := htmlTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
	}
}

func (m *Master) httpMinimize(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	corpus := make(map[string]bool)
	for _, mgr := range m.managers {
		resp, err := http.Get("http://" + mgr.http + "/current_corpus")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to query corpus from %v: %v", mgr.name, err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to query corpus from %v: %v", mgr.name, err), http.StatusInternalServerError)
			return
		}
		var hashes []string
		err = json.Unmarshal(data, &hashes)
		if err != nil || len(hashes) == 0 {
			http.Error(w, fmt.Sprintf("failed to parse corpus from %v: %v", mgr.name, err), http.StatusInternalServerError)
			return
		}
		for _, hash := range hashes {
			corpus[hash] = true
		}
	}
	orig := len(m.corpus.m)
	m.corpus.minimize(corpus)
	fmt.Printf("minimized: %v -> %v -> %v\n", orig, len(corpus), len(m.corpus.m))
	for _, mgr := range m.managers {
		mgr.input = 0
	}
}

type UIData struct {
	CorpusLen int
	Managers  []UIManager
}

type UIManager struct {
	Name string
	Http string
}

var htmlTemplate = template.Must(template.New("").Parse(`
<!doctype html>
<html>
<head>
    <title>syzkaller master</title>
</head>
<body>
Corpus: {{.CorpusLen}} <br>
{{if .Managers}}
	Managers:<br>
	{{range $mgr := $.Managers}}
		<a href='http://{{$mgr.Http}}'>{{$mgr.Name}}</a><br>
	{{end}}
{{else}}
	No managers connected<br>
{{end}}
</body></html>
`))
