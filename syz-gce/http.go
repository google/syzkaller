// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	. "github.com/google/syzkaller/log"
)

func initHttp(addr string) {
	http.HandleFunc("/", httpSummary)
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
		Log: CachedLogOutput(),
	}
	if err := summaryTemplate.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func compileTemplate(html string) *template.Template {
	return template.Must(template.New("").Parse(strings.Replace(html, "{{STYLE}}", htmlStyle, -1)))
}

type UISummaryData struct {
	Log string
}

var summaryTemplate = compileTemplate(`
<!doctype html>
<html>
<head>
	<title>syz-gce</title>
	{{STYLE}}
</head>
<body>
<b>syz-gce</b>
<br>
<br>

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
