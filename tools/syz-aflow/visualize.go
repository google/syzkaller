// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Note: this file was entirely vibe-coded and is not reviewed properly.

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/goccy/go-graphviz"
	"github.com/google/syzkaller/pkg/aflow"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/encoding"
	"gonum.org/v1/gonum/graph/simple"
)

type vizNode struct {
	graph.Node
	name       string
	isAction   bool
	actionType string
	varType    string
	isInvis    bool
}

func (n vizNode) DOTID() string {
	return fmt.Sprintf("n%d", n.ID())
}

func (n vizNode) Attributes() []encoding.Attribute {
	if n.isInvis {
		return []encoding.Attribute{
			{Key: "shape", Value: `"point"`},
			{Key: "style", Value: `"invis"`},
			{Key: "width", Value: `"0"`},
			{Key: "height", Value: `"0"`},
		}
	}
	if n.isAction {
		label := n.name
		if n.actionType != "" {
			label = fmt.Sprintf("[%s]\n%s", n.actionType, label)
		}
		attrs := []encoding.Attribute{
			{Key: "label", Value: fmt.Sprintf("%q", label)},
			{Key: "shape", Value: `"box"`},
			{Key: "style", Value: `"bold"`},
			{Key: "penwidth", Value: `"3"`},
		}
		if n.actionType == "LLMAgent" {
			attrs = append(attrs, encoding.Attribute{Key: "color", Value: `"darkred"`}, encoding.Attribute{Key: "fontcolor", Value: `"darkred"`})
		}
		return attrs
	}

	attrs := []encoding.Attribute{
		{Key: "label", Value: fmt.Sprintf("%q", n.name)},
		{Key: "shape", Value: `"ellipse"`},
	}
	color := "black"
	penwidth := "2"
	if n.varType == "input" {
		color = "darkblue"
	} else if n.varType == "output" {
		color = "darkgreen"
		penwidth = "3"
	}
	if color != "black" {
		attrs = append(attrs, encoding.Attribute{Key: "color", Value: fmt.Sprintf("%q", color)}, encoding.Attribute{Key: "fontcolor", Value: fmt.Sprintf("%q", color)})
	}
	attrs = append(attrs, encoding.Attribute{Key: "penwidth", Value: fmt.Sprintf("%q", penwidth)})
	return attrs
}

type vizEdge struct {
	graph.Edge
	isInvis bool
}

func (e vizEdge) Attributes() []encoding.Attribute {
	if e.isInvis {
		return []encoding.Attribute{
			{Key: "style", Value: `"invis"`},
			{Key: "weight", Value: `"100"`},
		}
	}
	return []encoding.Attribute{
		{Key: "weight", Value: `"1"`},
	}
}

func visualizeGraph(flow *aflow.Flow) error {
	if flow.Graph == nil {
		return fmt.Errorf("workflow %q has no graph information available", flow.Name)
	}

	g := simple.NewDirectedGraph()

	actionNodesByName := make(map[string]vizNode)
	varNodesByName := make(map[string]vizNode)

	var seqNodes []vizNode

	type vizCluster struct {
		name     string
		label    string
		nodes    []string // DOTIDs
		ranks    []string // rank=same definitions
		clusters []*vizCluster
	}
	rootCluster := &vizCluster{name: "root"}
	var allClusters []*vizCluster
	clusterByActionName := make(map[string]*vizCluster)

	// Helper to add nodes recursively
	var addNodes func(n *aflow.ActionNode, currentCluster *vizCluster)
	addNodes = func(n *aflow.ActionNode, currentCluster *vizCluster) {
		if n == nil {
			return
		}

		thisCluster := currentCluster
		if n.Type == "If" || n.Type == "DoWhile" || n.Type == "ForEach" {
			thisCluster = &vizCluster{
				name:  fmt.Sprintf("cluster_%d", len(allClusters)),
				label: "",
			}
			allClusters = append(allClusters, thisCluster)
			currentCluster.clusters = append(currentCluster.clusters, thisCluster)
		} else if n.Branch != "" {
			thisCluster = &vizCluster{
				name:  fmt.Sprintf("cluster_%d", len(allClusters)),
				label: n.Branch,
			}
			allClusters = append(allClusters, thisCluster)
			currentCluster.clusters = append(currentCluster.clusters, thisCluster)
		}

		if n.Type != "Pipeline" {
			vn, ok := actionNodesByName[n.Name]
			if !ok {
				vn = vizNode{Node: g.NewNode(), name: n.Name, isAction: true, actionType: n.Type}
				actionNodesByName[n.Name] = vn
				g.AddNode(vn)
			}

			thisCluster.nodes = append(thisCluster.nodes, vn.DOTID())
			clusterByActionName[n.Name] = thisCluster
			seqNodes = append(seqNodes, vn)
		}

		for _, child := range n.Children {
			addNodes(child, thisCluster)
		}
	}
	addNodes(flow.Graph.Root, rootCluster)

	inputVars := make(map[string]bool)
	outputVars := make(map[string]bool)
	for _, e := range flow.Graph.Edges {
		if e.From == "flow inputs" || e.From == "flow consts" {
			inputVars[e.Var] = true
		}
		if e.To == "flow outputs" {
			outputVars[e.Var] = true
		}
	}

	varGrouped := make(map[string]bool)
	actionOutputVars := make(map[string][]string)

	var allEdges []vizEdge

	// Add variable nodes and edges
	for _, e := range flow.Graph.Edges {
		if e.From == "" || e.To == "" {
			continue
		}
		fromAction, ok1 := actionNodesByName[e.From]
		toAction, ok2 := actionNodesByName[e.To]

		varNode, ok := varNodesByName[e.Var]
		if !ok {
			varType := "other"
			if inputVars[e.Var] {
				varType = "input"
			} else if outputVars[e.Var] {
				varType = "output"
			}
			varNode = vizNode{Node: g.NewNode(), name: e.Var, isAction: false, varType: varType}
			varNodesByName[e.Var] = varNode
			g.AddNode(varNode)

			if varType == "input" {
				rootCluster.nodes = append(rootCluster.nodes, varNode.DOTID())
			}
		}

		if ok1 {
			if !g.HasEdgeFromTo(fromAction.ID(), varNode.ID()) {
				edge := vizEdge{Edge: g.NewEdge(fromAction, varNode)}
				g.SetEdge(edge)
				allEdges = append(allEdges, edge)
			}
			if (varNode.varType == "other" || varNode.varType == "output") && !varGrouped[varNode.name] {
				varGrouped[varNode.name] = true
				actionOutputVars[fromAction.name] = append(actionOutputVars[fromAction.name], varNode.DOTID())
				if c, ok := clusterByActionName[fromAction.name]; ok {
					c.nodes = append(c.nodes, varNode.DOTID())
				} else {
					rootCluster.nodes = append(rootCluster.nodes, varNode.DOTID())
				}
			}
		}
		if ok2 {
			if !g.HasEdgeFromTo(varNode.ID(), toAction.ID()) {
				edge := vizEdge{Edge: g.NewEdge(varNode, toAction)}
				g.SetEdge(edge)
				allEdges = append(allEdges, edge)
			}
		}
	}

	invisNodes := make(map[string]vizNode)
	for i := 0; i < len(seqNodes); i++ {
		actionNode := seqNodes[i]

		var lastNode graph.Node = actionNode

		vars := actionOutputVars[actionNode.name]
		if len(vars) > 0 {
			invis := vizNode{Node: g.NewNode(), name: "invis_" + actionNode.name, isAction: false, isInvis: true}
			invisNodes[actionNode.name] = invis
			g.AddNode(invis)

			edge := vizEdge{Edge: g.NewEdge(actionNode, invis), isInvis: true}
			g.SetEdge(edge)
			allEdges = append(allEdges, edge)
			lastNode = invis

			var targetCluster *vizCluster
			if c, ok := clusterByActionName[actionNode.name]; ok {
				c.nodes = append(c.nodes, invis.DOTID())
				targetCluster = c
			} else {
				rootCluster.nodes = append(rootCluster.nodes, invis.DOTID())
				targetCluster = rootCluster
			}

			targetCluster.ranks = append(targetCluster.ranks, fmt.Sprintf("{ rank=same; %s; %s; }", invis.DOTID(), strings.Join(vars, "; ")))
		}

		if i+1 < len(seqNodes) {
			nextActionNode := seqNodes[i+1]
			edge := vizEdge{Edge: g.NewEdge(lastNode, nextActionNode), isInvis: true}
			g.SetEdge(edge)
			allEdges = append(allEdges, edge)
		}
	}

	var builder strings.Builder
	builder.WriteString("strict digraph aflow {\n")

	allVizNodes := make(map[string]vizNode)
	for _, n := range actionNodesByName {
		allVizNodes[n.DOTID()] = n
	}
	for _, n := range varNodesByName {
		allVizNodes[n.DOTID()] = n
	}
	for _, n := range invisNodes {
		allVizNodes[n.DOTID()] = n
	}

	var writeClusters func(*vizCluster)
	writeClusters = func(c *vizCluster) {
		if c.name != "root" {
			builder.WriteString(fmt.Sprintf("\n  subgraph %s {\n", c.name))
			if c.label != "" {
				builder.WriteString(fmt.Sprintf("    label = %q;\n", c.label))
			}
		}
		for _, nodeID := range c.nodes {
			n := allVizNodes[nodeID]
			builder.WriteString(fmt.Sprintf("    %s [\n", n.DOTID()))
			for _, attr := range n.Attributes() {
				builder.WriteString(fmt.Sprintf("      %s=%s,\n", attr.Key, attr.Value))
			}
			builder.WriteString("    ];\n")
		}
		for _, rank := range c.ranks {
			builder.WriteString(fmt.Sprintf("    %s\n", rank))
		}
		for _, child := range c.clusters {
			writeClusters(child)
		}
		if c.name != "root" {
			builder.WriteString("  }\n")
		}
	}
	writeClusters(rootCluster)

	for _, e := range allEdges {
		builder.WriteString(fmt.Sprintf("  %s -> %s [\n", e.From().(vizNode).DOTID(), e.To().(vizNode).DOTID()))
		for _, attr := range e.Attributes() {
			builder.WriteString(fmt.Sprintf("    %s=%s,\n", attr.Key, attr.Value))
		}
		builder.WriteString("  ];\n")
	}

	var inputs []string
	for _, vn := range varNodesByName {
		if vn.varType == "input" {
			inputs = append(inputs, vn.DOTID())
		}
	}

	if len(inputs) > 0 {
		builder.WriteString(fmt.Sprintf("\n  { rank=source; %s; }\n", strings.Join(inputs, "; ")))
	}
	builder.WriteString("}\n")

	b := []byte(builder.String())

	parsedGraph, err := graphviz.ParseBytes(b)
	if err != nil {
		return fmt.Errorf("failed to parse dot graph: %w", err)
	}
	defer parsedGraph.Close()

	ctx := context.Background()
	gv, err := graphviz.New(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize graphviz: %w", err)
	}
	defer gv.Close()

	f, err := os.CreateTemp("", "aflow-graph-*.svg")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer f.Close()

	if err := gv.Render(ctx, parsedGraph, graphviz.SVG, f); err != nil {
		return fmt.Errorf("failed to render svg graph: %w", err)
	}

	fmt.Printf("generated graph in %v\n", f.Name())
	if err := exec.Command("xdg-open", f.Name()).Start(); err != nil {
		fmt.Printf("failed to open browser: %v\n", err)
	}
	return nil
}
