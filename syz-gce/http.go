// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	. "github.com/google/syzkaller/log"
)

func initHttp(addr string) {
	http.HandleFunc("/", httpManager)
	http.HandleFunc("/syz-gce", httpSummary)

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		Fatalf("failed to listen on %v: %v", addr, err)
	}
	Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		Fatalf("failed to serve http: %v", err)
	}()
}

func httpSummary(w http.ResponseWriter, r *http.Request) {
	data := &UISummaryData{
		Name:    cfg.Name,
		Manager: atomic.LoadUint32(&managerHttpPort) != 0,
		Log:     CachedLogOutput(),
	}
	if err := summaryTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func httpManager(w http.ResponseWriter, r *http.Request) {
	port := atomic.LoadUint32(&managerHttpPort)
	if port == 0 {
		http.Error(w, "manager is not running", http.StatusInternalServerError)
		return
	}
	resp, err := http.Get(fmt.Sprintf("http://localhost:%v/%v", port, r.RequestURI))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, resp.Body)
}

func compileTemplate(html string) *template.Template {
	return template.Must(template.New("").Parse(strings.Replace(html, "{{STYLE}}", htmlStyle, -1)))
}

type UISummaryData struct {
	Name    string
	Manager bool
	Log     string
}

var summaryTemplate = compileTemplate(`
<!doctype html>
<html>
<head>
	<title>{{.Name}} syz-gce</title>
	{{STYLE}}
</head>
<body>
<b>{{.Name}} syz-gce</b>
<br><br>

{{if .Manager}}
<a href="/">manager</a>
{{else}}
manager is not running
{{end}}
<br><br>

Log:
<br>
<textarea id="log_textarea" readonly rows="50">
{{.Log}}
</textarea>
<script>
	var textarea = document.getElementById("log_textarea");
	textarea.scrollTop = textarea.scrollHeight;
</script>

</body></html>
`)

const htmlStyle = `
	<style type="text/css" media="screen">
		table {
			border-collapse:collapse;
			border:1px solid;
		}
		table caption {
			font-weight: bold;
		}
		table td {
			border:1px solid;
			padding: 3px;
		}
		table th {
			border:1px solid;
			padding: 3px;
		}
		textarea {
			width:100%;
		}
	</style>
`
