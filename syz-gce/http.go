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
	if err := summaryTemplate.Execute(w, nil); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
		return
	}
}

func compileTemplate(html string) *template.Template {
	return template.Must(template.New("").Parse(strings.Replace(html, "{{STYLE}}", htmlStyle, -1)))
}

var summaryTemplate = compileTemplate(`
<!doctype html>
<html>
<head>
	<title>syz-gce</title>
	{{STYLE}}
</head>
<body>
syz-gce
</body></html>
`)

const htmlStyle = `
	<style type="text/css" media="screen">
		table {
			border-collapse:collapse;
			border:1px solid;
		}
		table td {
			border:1px solid;
		}
	</style>
`
