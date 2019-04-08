// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-benchcmp visualizes syz-manager benchmarking results.
// First, run syz-manager with -bench=old flag.
// Then, do experimental modifications and run syz-manager again with -bench=new flag.
// Then, run syz-benchcmp old new.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagSkip = flag.Int("skip", -30, "skip that many seconds after start (skip first 20% by default)")
)

type Graph struct {
	Name    string
	Headers []string
	Points  []Point
}

type Point struct {
	Time uint64
	Vals []uint64
}

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "usage: syz-benchcmp [flags] bench_file0 [bench_file1 [bench_file2]]...\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	graphs := []*Graph{
		{Name: "cover"},
		{Name: "corpus"},
		{Name: "exec total"},
		{Name: "crash types"},
	}
	for i, fname := range flag.Args() {
		data := readFile(fname)
		addExecSpeed(data)
		for _, g := range graphs {
			g.Headers = append(g.Headers, filepath.Base(fname))
			for _, v := range data {
				pt := Point{
					Time: v["fuzzing"],
					Vals: make([]uint64, len(flag.Args())),
				}
				pt.Vals[i] = v[g.Name]
				g.Points = append(g.Points, pt)
			}
		}
	}
	for _, g := range graphs {
		if len(g.Points) == 0 {
			failf("no data points")
		}
		sort.Sort(pointSlice(g.Points))
		skipStart(g)
		restoreMissingPoints(g)
	}
	printFinalStats(graphs)
	display(graphs)
}

func readFile(fname string) (data []map[string]uint64) {
	f, err := os.Open(fname)
	if err != nil {
		failf("failed to open input file: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReader(f))
	for dec.More() {
		v := make(map[string]uint64)
		if err := dec.Decode(&v); err != nil {
			failf("failed to decode input file %v: %v", fname, err)
		}
		data = append(data, v)
	}
	return
}

func addExecSpeed(data []map[string]uint64) {
	// Speed between consecutive samples is very unstable.
	const (
		window = 100
		step   = 10
	)
	for i := window; i < len(data); i += step {
		cur := data[i]
		prev := data[i-window]
		dx := cur["exec total"] - prev["exec total"]
		dt := cur["fuzzing"] - prev["fuzzing"]
		cur["exec speed"] = dx * 1000 / dt
	}
}

func skipStart(g *Graph) {
	skipTime := uint64(*flagSkip)
	if *flagSkip < 0 {
		// Negative skip means percents.
		max := g.Points[len(g.Points)-1].Time
		skipTime = max * -skipTime / 100
	}
	if skipTime > 0 {
		skip := sort.Search(len(g.Points), func(i int) bool {
			return g.Points[i].Time > skipTime
		})
		g.Points = g.Points[skip:]
	}
}

func restoreMissingPoints(g *Graph) {
	for i := range g.Headers {
		// Find previous and next non-zero point for each zero point,
		// and restore its value with linear inerpolation.
		type Pt struct {
			Time uint64
			Val  uint64
		}
		var prev Pt
		prevs := make(map[uint64]Pt)
		for _, pt := range g.Points {
			if pt.Vals[i] != 0 {
				prev = Pt{pt.Time, pt.Vals[i]}
				continue
			}
			prevs[pt.Time] = prev
		}
		var next Pt
		for pti := len(g.Points) - 1; pti >= 0; pti-- {
			pt := g.Points[pti]
			if pt.Vals[i] != 0 {
				next = Pt{pt.Time, pt.Vals[i]}
				continue
			}
			prev := prevs[pt.Time]
			if prev.Val == 0 || next.Val == 0 {
				continue
			}
			pt.Vals[i] = prev.Val
			if next.Time != prev.Time {
				// Use signed calculations as corpus can go backwards.
				pt.Vals[i] += uint64(int64(next.Val-prev.Val) * int64(pt.Time-prev.Time) / int64(next.Time-prev.Time))
			}
		}
	}
}

func printFinalStats(graphs []*Graph) {
	for i := 1; i < len(graphs[0].Headers); i++ {
		fmt.Printf("%-12v%16v%16v%16v\n", "", graphs[0].Headers[0], graphs[0].Headers[i], "diff")
		for _, g := range graphs {
			lastNonZero := func(x int) uint64 {
				for j := len(g.Points) - 1; j >= 0; j-- {
					if v := g.Points[j].Vals[x]; v != 0 {
						return v
					}
				}
				return 0
			}
			old := lastNonZero(0)
			new := lastNonZero(i)
			fmt.Printf("%-12v%16v%16v%+16d\n", g.Name, old, new, int64(new-old))
		}
		fmt.Printf("\n")
	}
}

func display(graphs []*Graph) {
	outf, err := ioutil.TempFile("", "")
	if err != nil {
		failf("failed to create temp file: %v", err)
	}
	if err := htmlTemplate.Execute(outf, graphs); err != nil {
		failf("failed to execute template: %v", err)
	}
	outf.Close()
	name := outf.Name() + ".html"
	if err := osutil.Rename(outf.Name(), name); err != nil {
		failf("failed to rename file: %v", err)
	}
	if err := exec.Command("xdg-open", name).Start(); err != nil {
		failf("failed to start browser: %v", err)
	}
}

type pointSlice []Point

func (a pointSlice) Len() int           { return len(a) }
func (a pointSlice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a pointSlice) Less(i, j int) bool { return a[i].Time < a[j].Time }

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

var htmlTemplate = template.Must(
	template.New("").Parse(`
<!doctype html>
<html>
  <head>
    <title>Syzkaller Bench</title>
    <script type="text/javascript" src="https://www.google.com/jsapi"></script>
    <script type="text/javascript">
      google.load("visualization", "1", {packages:["corechart"]});
      google.setOnLoadCallback(drawCharts);
      function drawCharts() {
        {{range $id, $graph := .}}
        {
          var data = new google.visualization.DataTable();
          data.addColumn({type: 'number'});
          {{range $graph.Headers}}
            data.addColumn({type: 'number', label: '{{.}}'});
          {{end}}
          data.addRows([
            {{range $graph.Points}} [ {{.Time}}, {{range .Vals}} {{if .}} {{.}} {{end}}, {{end}}
          ],
          {{end}}
          ]);
          new google.visualization.LineChart(document.getElementById('graph_div_{{$id}}')).
            draw(data, {
              title: '{{$graph.Name}}',
              width: "100%",
              height: document.documentElement.clientHeight * 0.48,
              legend: {position: "in"},
              focusTarget: "category",
              hAxis: {title: "Time, sec"},
              chartArea: {left: "5%", top: "5%", width: "90%", height:"85%"}
            })
        }
        {{end}}
      }
    </script>
</head>
<body>
  <table style="width: 100%; height: 98vh">
    <tr>
      <td style="width: 50%"> <div id="graph_div_0"></div> </td>
      <td style="width: 50%"> <div id="graph_div_2"></div> </td>
    </tr>
    <tr>
      <td style="width: 50%"> <div id="graph_div_1"></div> </td>
      <td style="width: 50%"> <div id="graph_div_3"></div> </td>
    </tr>
  </table>
</body>
</html>
`))
