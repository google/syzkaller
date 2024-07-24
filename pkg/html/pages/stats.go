// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package pages

var StatsTemplate = Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller stats</title>
	<script type="text/javascript" src="https://www.google.com/jsapi"></script>
	<script type="text/javascript">
		google.load("visualization", "1", {packages:["corechart"]});
		google.setOnLoadCallback(function() {
			{{range $g := .}}
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
			{{end}}

			{{/* Preserve vertical scroll position after page reloads. Otherwise it's random. */}}
			window.scroll(0, window.location.hash.substring(1));
			document.onscroll = function(e) { window.location.hash = Math.round(window.scrollY); };
		});
	</script>
	{{HEAD}}
</head>
<body>
{{range $g := .}}
	<div id="div_{{$g.ID}}"></div>
{{end}}
</body>
</html>
`)
