// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsm/histogram/v3"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/prometheus/client_golang/prometheus"
)

// This file provides prometheus/streamz style metrics (Val type) for instrumenting code for monitoring.
// It also provides a registry for such metrics (set type) and a global default registry.
//
// Simple uses of metrics:
//
//	statFoo := stats.Create("metric name", "metric description")
//	statFoo.Add(1)
//
//	stats.Create("metric name", "metric description", LenOf(mySlice, rwMutex))
//
// Metric visualization code uses Collect/RenderHTML functions to obtain values of all registered metrics.

type UI struct {
	Name  string
	Desc  string
	Link  string
	Level Level
	Value string
	V     int
}

func Create(name, desc string, opts ...any) *Val {
	return global.Create(name, desc, opts...)
}

func Collect(level Level) []UI {
	return global.Collect(level)
}

func RenderHTML() ([]byte, error) {
	return global.RenderHTML()
}

func Import(named map[string]uint64) {
	global.Import(named)
}

var global = newSet(256, true)

type set struct {
	mu           sync.Mutex
	vals         map[string]*Val
	graphs       map[string]*graph
	totalTicks   int
	historySize  int
	historyTicks int
	historyPos   int
	historyScale int
}

type graph struct {
	level   Level
	stacked bool
	lines   map[string]*line
}

type line struct {
	desc string
	rate bool
	data []float64
	hist []*histogram.Histogram
}

const (
	tickPeriod       = time.Second
	histogramBuckets = 255
)

func newSet(histSize int, tick bool) *set {
	s := &set{
		vals:         make(map[string]*Val),
		historySize:  histSize,
		historyScale: 1,
		graphs:       make(map[string]*graph),
	}
	if tick {
		go func() {
			for range time.NewTicker(tickPeriod).C {
				s.tick()
			}
		}()
	}
	return s
}

func (s *set) Collect(level Level) []UI {
	s.mu.Lock()
	defer s.mu.Unlock()
	period := time.Duration(s.totalTicks) * tickPeriod
	if period == 0 {
		period = tickPeriod
	}
	var res []UI
	for _, v := range s.vals {
		if v.level < level {
			continue
		}
		val := v.Val()
		res = append(res, UI{
			Name:  v.name,
			Desc:  v.desc,
			Link:  v.link,
			Level: v.level,
			Value: v.fmt(val, period),
			V:     val,
		})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Level != res[j].Level {
			return res[i].Level > res[j].Level
		}
		return res[i].Name < res[j].Name
	})
	return res
}

func (s *set) Import(named map[string]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, val := range named {
		v := s.vals[name]
		if v == nil {
			panic(fmt.Sprintf("imported stat %v is missing", name))
		}
		v.Add(int(val))
	}
}

// Additional options for Val metrics.

// Level controls if the metric should be printed to console in periodic heartbeat logs,
// or showed on the simple web interface, or showed in the expert interface only.
type Level int

const (
	All Level = iota
	Simple
	Console
)

// Link adds a hyperlink to metric name.
type Link string

// Prometheus exports the metric to Prometheus under the given name.
type Prometheus string

// Rate says to collect/visualize metric rate per unit of time rather then total value.
type Rate struct{}

// Distribution says to collect/visualize histogram of individual sample distributions.
type Distribution struct{}

// Graph allows to combine multiple related metrics on a single graph.
type Graph string

// StackedGraph is like Graph, but shows metrics on a stacked graph.
type StackedGraph string

// NoGraph says to not visualize the metric as a graph.
const NoGraph Graph = ""

// LenOf reads the metric value from the given slice/map/chan.
func LenOf(containerPtr any, mu *sync.RWMutex) func() int {
	v := reflect.ValueOf(containerPtr)
	_ = v.Elem().Len() // panics if container is not slice/map/chan
	return func() int {
		mu.RLock()
		defer mu.RUnlock()
		return v.Elem().Len()
	}
}

func FormatMB(v int, period time.Duration) string {
	const KB, MB = 1 << 10, 1 << 20
	return fmt.Sprintf("%v MB (%v kb/sec)", (v+MB/2)/MB, (v+KB/2)/KB/int(period/time.Second))
}

// Addittionally a custom 'func() int' can be passed to read the metric value from the function.
// and 'func(int, time.Duration) string' can be passed for custom formatting of the metric value.

func (s *set) Create(name, desc string, opts ...any) *Val {
	v := &Val{
		name:  name,
		desc:  desc,
		graph: name,
		fmt:   func(v int, period time.Duration) string { return strconv.Itoa(v) },
	}
	stacked := false
	for _, o := range opts {
		switch opt := o.(type) {
		case Level:
			v.level = opt
		case Link:
			v.link = string(opt)
		case Graph:
			v.graph = string(opt)
		case StackedGraph:
			v.graph = string(opt)
			stacked = true
		case Rate:
			v.rate = true
			v.fmt = formatRate
		case Distribution:
			v.hist = true
		case func() int:
			v.ext = opt
		case func(int, time.Duration) string:
			v.fmt = opt
		case Prometheus:
			// Prometheus Instrumentation https://prometheus.io/docs/guides/go-application.
			prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
				Name: string(opt),
				Help: desc,
			},
				func() float64 { return float64(v.Val()) },
			))
		default:
			panic(fmt.Sprintf("unknown stats option %#v", o))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vals[name] = v
	if v.graph != "" {
		if s.graphs[v.graph] == nil {
			s.graphs[v.graph] = &graph{
				lines: make(map[string]*line),
			}
		}
		if s.graphs[v.graph].level < v.level {
			s.graphs[v.graph].level = v.level
		}
		s.graphs[v.graph].stacked = stacked
	}
	return v
}

type Val struct {
	name    string
	desc    string
	link    string
	graph   string
	level   Level
	val     atomic.Uint64
	ext     func() int
	fmt     func(int, time.Duration) string
	rate    bool
	hist    bool
	prev    int
	histMu  sync.Mutex
	histVal *histogram.Histogram
}

func (v *Val) Add(val int) {
	if v.ext != nil {
		panic(fmt.Sprintf("stat %v is in external mode", v.name))
	}
	if v.hist {
		v.histMu.Lock()
		if v.histVal == nil {
			v.histVal = histogram.New(histogramBuckets)
		}
		v.histVal.Add(float64(val))
		v.histMu.Unlock()
		return
	}
	v.val.Add(uint64(val))
}

func (v *Val) Val() int {
	if v.ext != nil {
		return v.ext()
	}
	if v.hist {
		v.histMu.Lock()
		defer v.histMu.Unlock()
		if v.histVal == nil {
			return 0
		}
		return int(v.histVal.Mean())
	}
	return int(v.val.Load())
}

func formatRate(v int, period time.Duration) string {
	secs := int(period.Seconds())
	if x := v / secs; x >= 10 {
		return fmt.Sprintf("%v (%v/sec)", v, x)
	}
	if x := v * 60 / secs; x >= 10 {
		return fmt.Sprintf("%v (%v/min)", v, x)
	}
	x := v * 60 * 60 / secs
	return fmt.Sprintf("%v (%v/hour)", v, x)
}

func (s *set) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.historyPos == s.historySize {
		s.compress()
	}

	s.totalTicks++
	s.historyTicks++
	for _, v := range s.vals {
		if v.graph == "" {
			continue
		}
		graph := s.graphs[v.graph]
		ln := graph.lines[v.name]
		if ln == nil {
			ln = &line{
				desc: v.desc,
				rate: v.rate,
			}
			if v.hist {
				ln.hist = make([]*histogram.Histogram, s.historySize)
			} else {
				ln.data = make([]float64, s.historySize)
			}
			graph.lines[v.name] = ln
		}
		if v.hist {
			if s.historyTicks == s.historyScale {
				v.histMu.Lock()
				ln.hist[s.historyPos] = v.histVal
				v.histVal = nil
				v.histMu.Unlock()
			}
		} else {
			val := v.Val()
			pv := &ln.data[s.historyPos]
			if v.rate {
				*pv += float64(val-v.prev) / float64(s.historyScale)
				v.prev = val
			} else {
				if *pv < float64(val) {
					*pv = float64(val)
				}
			}
		}
	}
	if s.historyTicks != s.historyScale {
		return
	}
	s.historyTicks = 0
	s.historyPos++
}

func (s *set) compress() {
	half := s.historySize / 2
	s.historyPos = half
	s.historyScale *= 2
	for _, graph := range s.graphs {
		for _, line := range graph.lines {
			for i := 0; i < half; i++ {
				if line.hist != nil {
					h1, h2 := line.hist[2*i], line.hist[2*i+1]
					line.hist[2*i], line.hist[2*i+1] = nil, nil
					line.hist[i] = h1
					if h1 == nil {
						line.hist[i] = h2
					}
				} else {
					v1, v2 := line.data[2*i], line.data[2*i+1]
					line.data[2*i], line.data[2*i+1] = 0, 0
					if line.rate {
						line.data[i] = (v1 + v2) / 2
					} else {
						line.data[i] = v1
						if v2 > v1 {
							line.data[i] = v2
						}
					}
				}
			}
		}
	}
}

func (s *set) RenderHTML() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type Point struct {
		X int
		Y []float64
	}
	type Graph struct {
		ID      int
		Title   string
		Stacked bool
		Level   Level
		Lines   []string
		Points  []Point
	}
	var graphs []Graph
	tick := s.historyScale * int(tickPeriod.Seconds())
	for title, graph := range s.graphs {
		if len(graph.lines) == 0 {
			continue
		}
		g := Graph{
			ID:      len(graphs),
			Title:   title,
			Stacked: graph.stacked,
			Level:   graph.level,
			Points:  make([]Point, s.historyPos),
		}
		for i := 0; i < s.historyPos; i++ {
			g.Points[i].X = i * tick
		}
		for name, ln := range graph.lines {
			if ln.hist == nil {
				g.Lines = append(g.Lines, name+": "+ln.desc)
				for i := 0; i < s.historyPos; i++ {
					g.Points[i].Y = append(g.Points[i].Y, ln.data[i])
				}
			} else {
				for _, percent := range []int{10, 50, 90} {
					g.Lines = append(g.Lines, fmt.Sprintf("%v%%", percent))
					for i := 0; i < s.historyPos; i++ {
						v := 0.0
						if ln.hist[i] != nil {
							v = ln.hist[i].Quantile(float64(percent) / 100)
						}
						g.Points[i].Y = append(g.Points[i].Y, v)
					}
				}
			}
		}
		graphs = append(graphs, g)
	}
	sort.Slice(graphs, func(i, j int) bool {
		if graphs[i].Level != graphs[j].Level {
			return graphs[i].Level > graphs[j].Level
		}
		return graphs[i].Title < graphs[j].Title
	})
	buf := new(bytes.Buffer)
	err := htmlTemplate.Execute(buf, graphs)
	return buf.Bytes(), err
}

var htmlTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller stats</title>
	<script type="text/javascript" src="https://www.google.com/jsapi"></script>
	{{HEAD}}
</head>
<body>
{{range $g := .}}
	<div id="div_{{$g.ID}}"></div>
	<script type="text/javascript">
		google.load("visualization", "1", {packages:["corechart"]});
		google.setOnLoadCallback(function() {
			new google.visualization. {{if $g.Stacked}} AreaChart {{else}} LineChart {{end}} (
				document.getElementById('div_{{$g.ID}}')).
				draw(google.visualization.arrayToDataTable([
					["-" {{range $line := $g.Lines}} , '{{$line}}' {{end}}],
					{{range $p := $g.Points}} [ {{$p.X}} {{range $y := $p.Y}} , {{$y}} {{end}} ], {{end}}
				]), {
					title: '{{$g.Title}}',
					titlePosition: 'in',
					width: "95%",
					height: "400",
					chartArea: {width: '95%', height: '85%'},
					legend: {position: 'in'},
					lineWidth: 2,
					focusTarget: "category",
					{{if $g.Stacked}} isStacked: true, {{end}}
					vAxis: {minValue: 1, textPosition: 'in', gridlines: {multiple: 1}, minorGridlines: {multiple: 1}},
					hAxis: {minValue: 1, textPosition: 'out', maxAlternation: 1, gridlines: {multiple: 1},
						minorGridlines: {multiple: 1}},
				})
		});
	</script>
{{end}}
</body>
</html>
`)
