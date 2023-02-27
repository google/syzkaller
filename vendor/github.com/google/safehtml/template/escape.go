// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"fmt"
	"html"
	"reflect"
	"strings"
	"text/template"
	"text/template/parse"
)

// TODO: remove all unused escaping logic inherited from html/template.
// TODO: replace "escape" with "sanitize" in file names and contents to maintain consistency with safehtml/template docs.

// escapeTemplate rewrites the named template, which must be
// associated with t, to guarantee that the output of any of the named
// templates is properly escaped. If no error is returned, then the named templates have
// been modified. Otherwise the named templates have been rendered
// unusable.
func escapeTemplate(tmpl *Template, node parse.Node, name string) error {
	c, _ := tmpl.esc.escapeTree(context{}, node, name, 0)
	var err error
	if c.err != nil {
		err, c.err.Name = c.err, name
	} else if c.state != stateText {
		err = &Error{ErrEndContext, nil, name, 0, fmt.Sprintf("ends in a non-text context: %+v", c)}
	}
	if err != nil {
		// Prevent execution of unsafe templates.
		if t := tmpl.set[name]; t != nil {
			t.escapeErr = err
			t.text.Tree = nil
			t.Tree = nil
		}
		return err
	}
	tmpl.esc.commit()
	if t := tmpl.set[name]; t != nil {
		t.escapeErr = errEscapeOK
		t.Tree = t.text.Tree
	}
	return nil
}

// evalArgs formats the list of arguments into a string. It is equivalent to
// fmt.Sprint(args...), except that it deferences all pointers.
func evalArgs(args ...interface{}) string {
	// Optimization for simple common case of a single string argument.
	if len(args) == 1 {
		if s, ok := args[0].(string); ok {
			return s
		}
	}
	for i, arg := range args {
		args[i] = indirectToStringerOrError(arg)
	}
	return fmt.Sprint(args...)
}

// escaper collects type inferences about templates and changes needed to make
// templates injection safe.
type escaper struct {
	// ns is the nameSpace that this escaper is associated with.
	ns *nameSpace
	// output[templateName] is the output context for a templateName that
	// has been mangled to include its input context.
	output map[string]context
	// derived[c.mangle(name)] maps to a template derived from the template
	// named name templateName for the start context c.
	derived map[string]*template.Template
	// called[templateName] is a set of called mangled template names.
	called map[string]bool
	// xxxNodeEdits are the accumulated edits to apply during commit.
	// Such edits are not applied immediately in case a template set
	// executes a given template in different escaping contexts.
	actionNodeEdits   map[*parse.ActionNode][]string
	templateNodeEdits map[*parse.TemplateNode]string
	textNodeEdits     map[*parse.TextNode][]byte
}

// makeEscaper creates a blank escaper for the given set.
func makeEscaper(n *nameSpace) escaper {
	return escaper{
		n,
		map[string]context{},
		map[string]*template.Template{},
		map[string]bool{},
		map[*parse.ActionNode][]string{},
		map[*parse.TemplateNode]string{},
		map[*parse.TextNode][]byte{},
	}
}

// escape escapes a template node.
func (e *escaper) escape(c context, n parse.Node) context {
	switch n := n.(type) {
	case *parse.ActionNode:
		return e.escapeAction(c, n)
	case *parse.IfNode:
		return e.escapeBranch(c, &n.BranchNode, "if")
	case *parse.ListNode:
		return e.escapeList(c, n)
	case *parse.RangeNode:
		return e.escapeBranch(c, &n.BranchNode, "range")
	case *parse.TemplateNode:
		return e.escapeTemplate(c, n)
	case *parse.TextNode:
		return e.escapeText(c, n)
	case *parse.WithNode:
		return e.escapeBranch(c, &n.BranchNode, "with")
	}
	panic("escaping " + n.String() + " is unimplemented")
}

// escapeAction escapes an action template node.
func (e *escaper) escapeAction(c context, n *parse.ActionNode) context {
	if len(n.Pipe.Decl) != 0 {
		// A local variable assignment, not an interpolation.
		return c
	}
	c = nudge(c)
	// Check for disallowed use of predefined escapers in the pipeline.
	for pos, idNode := range n.Pipe.Cmds {
		node, ok := idNode.Args[0].(*parse.IdentifierNode)
		if !ok {
			// A predefined escaper "esc" will never be found as an identifier in a
			// Chain or Field node, since:
			// - "esc.x ..." is invalid, since predefined escapers return strings, and
			//   strings do not have methods, keys or fields.
			// - "... .esc" is invalid, since predefined escapers are global functions,
			//   not methods or fields of any types.
			// Therefore, it is safe to ignore these two node types.
			continue
		}
		ident := node.Ident
		if _, ok := predefinedEscapers[ident]; ok {
			if pos < len(n.Pipe.Cmds)-1 ||
				c.state == stateAttr && c.delim == delimSpaceOrTagEnd && ident == "html" {
				return context{
					state: stateError,
					err:   errorf(ErrPredefinedEscaper, n, n.Line, "predefined escaper %q disallowed in template", ident),
				}
			}
		}
	}
	switch c.state {
	case stateError:
		return c
	case stateAttrName, stateTag:
		c.state = stateAttrName
	}
	// TODO: integrate sanitizerForContext into escapeAction.
	s, err := sanitizerForContext(c)
	if err != nil {
		return context{
			state: stateError,
			// TODO: return sanitization-specific errors.
			err: errorf(ErrEscapeAction, n, n.Line, "cannot escape action %v: %s", n, err),
		}
	}
	e.editActionNode(n, s)
	return c
}

// ensurePipelineContains ensures that the pipeline ends with the commands with
// the identifiers in s in order. If the pipeline ends with a predefined escaper
// (i.e. "html" or "urlquery"), merge it with the identifiers in s.c
func ensurePipelineContains(p *parse.PipeNode, s []string) {
	if len(s) == 0 {
		// Do not rewrite pipeline if we have no escapers to insert.
		return
	}
	// Precondition: p.Cmds contains at most one predefined escaper and the
	// escaper will be present at p.Cmds[len(p.Cmds)-1]. This precondition is
	// always true because of the checks in escapeAction.
	pipelineLen := len(p.Cmds)
	if pipelineLen > 0 {
		lastCmd := p.Cmds[pipelineLen-1]
		if idNode, ok := lastCmd.Args[0].(*parse.IdentifierNode); ok {
			if esc := idNode.Ident; predefinedEscapers[esc] {
				// Pipeline ends with a predefined escaper.
				if len(p.Cmds) == 1 && len(lastCmd.Args) > 1 {
					// Special case: pipeline is of the form {{ esc arg1 arg2 ... argN }},
					// where esc is the predefined escaper, and arg1...argN are its arguments.
					// Convert this into the equivalent form
					// {{ _eval_args_ arg1 arg2 ... argN | esc }}, so that esc can be easily
					// merged with the escapers in s.
					lastCmd.Args[0] = parse.NewIdentifier(evalArgsFuncName).SetTree(nil).SetPos(lastCmd.Args[0].Position())
					p.Cmds = append(p.Cmds, newIdentCmd(esc, p.Position()))
					pipelineLen++
				}
				// If any of the commands in s that we are about to insert is equivalent
				// to the predefined escaper, use the predefined escaper instead.
				dup := false
				for i, escaper := range s {
					if escFnsEq(esc, escaper) {
						s[i] = idNode.Ident
						dup = true
					}
				}
				if dup {
					// The predefined escaper will already be inserted along with the
					// escapers in s, so do not copy it to the rewritten pipeline.
					pipelineLen--
				}
			}
		}
	}
	// Rewrite the pipeline, creating the escapers in s at the end of the pipeline.
	newCmds := make([]*parse.CommandNode, pipelineLen, pipelineLen+len(s))
	copy(newCmds, p.Cmds)
	for _, name := range s {
		newCmds = append(newCmds, newIdentCmd(name, p.Position()))
	}
	p.Cmds = newCmds
}

// predefinedEscapers contains template predefined escapers that are equivalent
// to some contextual escapers. Keep in sync with equivEscapers.
var predefinedEscapers = map[string]bool{
	"html":     true,
	"urlquery": true,
}

// equivEscapers matches contextual escapers to equivalent predefined
// template escapers.
var equivEscapers = map[string]string{
	// The following pairs of HTML escapers provide equivalent security
	// guarantees, since they all escape '\000', '\'', '"', '&', '<', and '>'.
	sanitizeHTMLFuncName:   "html",
	sanitizeRCDATAFuncName: "html",
	// These two URL escapers produce URLs safe for embedding in a URL query by
	// percent-encoding all the reserved characters specified in RFC 3986 Section
	// 2.2
	queryEscapeURLFuncName: "urlquery",
	// The normalizer function is not actually equivalent to urlquery; urlquery is
	// stricter as it escapes reserved characters (e.g. '#'), while the normalizer
	// function does not. It is therefore only safe to replace the normalizer with
	// with urlquery (this happens in ensurePipelineContains), but not the other
	// way around. We keep this entry around to preserve the behavior of templates
	// written before Go 1.9, which might depend on this substitution taking place.
	normalizeURLFuncName: "urlquery",
}

// escFnsEq reports whether the two escaping functions are equivalent.
func escFnsEq(a, b string) bool {
	return normalizeEscFn(a) == normalizeEscFn(b)
}

// normalizeEscFn(a) is equal to normalizeEscFn(b) for any pair of names of
// escaper functions a and b that are equivalent.
func normalizeEscFn(e string) string {
	if norm := equivEscapers[e]; norm != "" {
		return norm
	}
	return e
}

// newIdentCmd produces a command containing a single identifier node.
func newIdentCmd(identifier string, pos parse.Pos) *parse.CommandNode {
	return &parse.CommandNode{
		NodeType: parse.NodeCommand,
		Args:     []parse.Node{parse.NewIdentifier(identifier).SetTree(nil).SetPos(pos)}, // TODO: SetTree.
		Pos:      pos,
	}
}

// nudge returns the context that would result from following empty string
// transitions from the input context.
// For example, parsing:
//     `<a href=`
// will end in context{stateBeforeValue, AttrURL}, but parsing one extra rune:
//     `<a href=x`
// will end in context{stateURL, delimSpaceOrTagEnd, ...}.
// There are two transitions that happen when the 'x' is seen:
// (1) Transition from a before-value state to a start-of-value state without
//     consuming any character.
// (2) Consume 'x' and transition past the first value character.
// In this case, nudging produces the context after (1) happens.
func nudge(c context) context {
	switch c.state {
	case stateTag:
		// In `<foo {{.}}`, the action should emit an attribute.
		c.state = stateAttrName
	case stateBeforeValue:
		// In `<foo bar={{.}}`, the action is an undelimited value.
		c.state, c.delim = stateAttr, delimSpaceOrTagEnd
	case stateAfterName:
		// In `<foo bar {{.}}`, the action is an attribute name.
		c.state = stateAttrName
	}
	return c
}

// join joins the two contexts of a branch template node. The result is an
// error context if either of the input contexts are error contexts, or if the
// input contexts differ.
func join(a, b context, node parse.Node, nodeName string) context {
	if a.state == stateError {
		return a
	}
	if b.state == stateError {
		return b
	}

	// Accumulate the result of context-joining elements and attributes in a, since the
	// contents of a are always returned.
	a.element.names = joinNames(a.element.name, b.element.name, a.element.names, b.element.names)
	a.attr.names = joinNames(a.attr.name, b.attr.name, a.attr.names, b.attr.names)
	if a.attr.value != b.attr.value {
		a.attr.ambiguousValue = true
	}

	if a.eq(b) {
		return a
	}

	c := a
	c.element.name = b.element.name
	if c.eq(b) {
		// The contexts differ only by their element names. The element names from the conditional
		// branches that are accumulated in c.element.names will be checked during action sanitization
		// to ensure that they do not lead to different sanitization contexts.
		return c
	}

	c = a
	c.attr.name = b.attr.name
	if c.eq(b) {
		// The contexts differ only by their attribute name. The attribute names from the conditional
		// branches that are accumulated in c.attr.names will be checked during action sanitization
		// to ensure that they do not lead to different sanitization contexts.
		return c
	}

	// Allow a nudged context to join with an unnudged one.
	// This means that
	//   <p title={{if .C}}{{.}}{{end}}
	// ends in an unquoted value state even though the else branch
	// ends in stateBeforeValue.
	if c, d := nudge(a), nudge(b); !(c.eq(a) && d.eq(b)) {
		if e := join(c, d, node, nodeName); e.state != stateError {
			return e
		}
	}

	return context{
		state: stateError,
		err:   errorf(ErrBranchEnd, node, 0, "{{%s}} branches end in different contexts: %v, %v", nodeName, a, b),
	}
}

// joinNames returns the slice of all possible names that an element or attr could
// assume after context joining the element or attr containing aName and aNames with the
// element or attr containing bName and bNames.
func joinNames(aName, bName string, aNames, bNames []string) []string {
	var ret []string
	if aName != bName {
		ret = append(ret, aName, bName)
	}
	aNamesSet := make(map[string]bool)
	for _, name := range aNames {
		aNamesSet[name] = true
	}
	for _, name := range bNames {
		if !aNamesSet[name] {
			ret = append(ret, name)
		}
	}
	return ret
}

// escapeBranch escapes a branch template node: "if", "range" and "with".
func (e *escaper) escapeBranch(c context, n *parse.BranchNode, nodeName string) context {
	c0 := e.escapeList(c, n.List)
	if nodeName == "range" && c0.state != stateError {
		// The "true" branch of a "range" node can execute multiple times.
		// We check that executing n.List once results in the same context
		// as executing n.List twice.
		c1, _ := e.escapeListConditionally(c0, n.List, nil)
		c0 = join(c0, c1, n, nodeName)
		if c0.state == stateError {
			// Make clear that this is a problem on loop re-entry
			// since developers tend to overlook that branch when
			// debugging templates.
			c0.err.Line = n.Line
			c0.err.Description = "on range loop re-entry: " + c0.err.Description
			return c0
		}
	}
	c1 := e.escapeList(c, n.ElseList)
	return join(c0, c1, n, nodeName)
}

// escapeList escapes a list template node.
func (e *escaper) escapeList(c context, n *parse.ListNode) context {
	if n == nil {
		return c
	}
	for _, m := range n.Nodes {
		c = e.escape(c, m)
	}
	return c
}

// escapeListConditionally escapes a list node but only preserves edits and
// inferences in e if the inferences and output context satisfy filter.
// It returns the best guess at an output context, and the result of the filter
// which is the same as whether e was updated.
func (e *escaper) escapeListConditionally(c context, n *parse.ListNode, filter func(*escaper, context) bool) (context, bool) {
	e1 := makeEscaper(e.ns)
	// Make type inferences available to f.
	for k, v := range e.output {
		e1.output[k] = v
	}
	c = e1.escapeList(c, n)
	ok := filter != nil && filter(&e1, c)
	if ok {
		// Copy inferences and edits from e1 back into e.
		for k, v := range e1.output {
			e.output[k] = v
		}
		for k, v := range e1.derived {
			e.derived[k] = v
		}
		for k, v := range e1.called {
			e.called[k] = v
		}
		for k, v := range e1.actionNodeEdits {
			e.editActionNode(k, v)
		}
		for k, v := range e1.templateNodeEdits {
			e.editTemplateNode(k, v)
		}
		for k, v := range e1.textNodeEdits {
			e.editTextNode(k, v)
		}
	}
	return c, ok
}

// escapeTemplate escapes a {{template}} call node.
func (e *escaper) escapeTemplate(c context, n *parse.TemplateNode) context {
	c, name := e.escapeTree(c, n, n.Name, n.Line)
	if name != n.Name {
		e.editTemplateNode(n, name)
	}
	return c
}

// mangle produces an identifier that includes a suffix that distinguishes it
// from template names mangled with different contexts.
func mangle(c context, templateName string) string {
	// The mangled name for the default context is the input templateName.
	if c.state == stateText {
		return templateName
	}
	s := templateName + "$htmltemplate_" + c.state.String()
	if c.delim != 0 {
		s += "_" + c.delim.String()
	}
	if c.attr.name != "" {
		s += "_" + c.attr.String()
	}
	if c.element.name != "" {
		s += "_" + c.element.String()
	}
	return s
}

// escapeTree escapes the named template starting in the given context as
// necessary and returns its output context.
func (e *escaper) escapeTree(c context, node parse.Node, name string, line int) (context, string) {
	// Mangle the template name with the input context to produce a reliable
	// identifier.
	dname := mangle(c, name)
	e.called[dname] = true
	if out, ok := e.output[dname]; ok {
		// Already escaped.
		return out, dname
	}
	t := e.template(name)
	if t == nil {
		// Two cases: The template exists but is empty, or has never been mentioned at
		// all. Distinguish the cases in the error messages.
		if e.ns.set[name] != nil {
			return context{
				state: stateError,
				err:   errorf(ErrNoSuchTemplate, node, line, "%q is an incomplete or empty template", name),
			}, dname
		}
		return context{
			state: stateError,
			err:   errorf(ErrNoSuchTemplate, node, line, "no such template %q", name),
		}, dname
	}
	if dname != name {
		// Use any template derived during an earlier call to escapeTemplate
		// with different top level templates, or clone if necessary.
		dt := e.template(dname)
		if dt == nil {
			dt = template.New(dname)
			dt.Tree = t.Tree.Copy()
			dt.Tree.Name = dname
			e.derived[dname] = dt
		}
		t = dt
	}
	return e.computeOutCtx(c, t), dname
}

// computeOutCtx takes a template and its start context and computes the output
// context while storing any inferences in e.
func (e *escaper) computeOutCtx(c context, t *template.Template) context {
	// Propagate context over the body.
	c1, ok := e.escapeTemplateBody(c, t)
	if !ok {
		// Look for a fixed point by assuming c1 as the output context.
		if c2, ok2 := e.escapeTemplateBody(c1, t); ok2 {
			c1, ok = c2, true
		}
		// Use c1 as the error context if neither assumption worked.
	}
	if !ok && c1.state != stateError {
		return context{
			state: stateError,
			err:   errorf(ErrOutputContext, t.Tree.Root, 0, "cannot compute output context for template %s", t.Name()),
		}
	}
	return c1
}

// escapeTemplateBody escapes the given template assuming the given output
// context, and returns the best guess at the output context and whether the
// assumption was correct.
func (e *escaper) escapeTemplateBody(c context, t *template.Template) (context, bool) {
	filter := func(e1 *escaper, c1 context) bool {
		if c1.state == stateError {
			// Do not update the input escaper, e.
			return false
		}
		if !e1.called[t.Name()] {
			// If t is not recursively called, then c1 is an
			// accurate output context.
			return true
		}
		// c1 is accurate if it matches our assumed output context.
		return c.eq(c1)
	}
	// We need to assume an output context so that recursive template calls
	// take the fast path out of escapeTree instead of infinitely recursing.
	// Naively assuming that the input context is the same as the output
	// works >90% of the time.
	e.output[t.Name()] = c
	return e.escapeListConditionally(c, t.Tree.Root, filter)
}

// delimEnds maps each delim to a string of characters that terminate it.
var delimEnds = [...]string{
	delimDoubleQuote: `"`,
	delimSingleQuote: "'",
	// Determined empirically by running the below in various browsers.
	// var div = document.createElement("DIV");
	// for (var i = 0; i < 0x10000; ++i) {
	//   div.innerHTML = "<span title=x" + String.fromCharCode(i) + "-bar>";
	//   if (div.getElementsByTagName("SPAN")[0].title.indexOf("bar") < 0)
	//     document.write("<p>U+" + i.toString(16));
	// }
	delimSpaceOrTagEnd: " \t\n\f\r>",
}

var doctypeBytes = []byte("<!DOCTYPE")

// escapeText escapes a text template node.
func (e *escaper) escapeText(c context, n *parse.TextNode) context {
	s, written, i, b := n.Text, 0, 0, new(bytes.Buffer)
	if e.ns.cspCompatible && bytes.Contains(s, []byte("javascript:")) {
		// This substring search is not perfect, but it is unlikely that this substring will
		// exist in template text for any other reason than to specify a javascript URI.
		return context{
			state: stateError,
			err:   errorf(ErrCSPCompatibility, n, 0, `"javascript:" URI disallowed for CSP compatibility`),
		}
	}
	for i != len(s) {
		if e.ns.cspCompatible && strings.HasPrefix(c.attr.name, "on") {
			return context{
				state: stateError,
				err:   errorf(ErrCSPCompatibility, n, 0, "inline event handler %q is disallowed for CSP compatibility", c.attr.name),
			}
		}
		c1, nread := contextAfterText(c, s[i:])
		i1 := i + nread
		sc, err := sanitizationContextForElementContent(c.element.name)
		if c.state == stateText || err == nil && sc == sanitizationContextRCDATA {
			end := i1
			if c1.state != c.state {
				for j := end - 1; j >= i; j-- {
					if s[j] == '<' {
						end = j
						break
					}
				}
			}
			for j := i; j < end; j++ {
				if s[j] == '<' && !bytes.HasPrefix(bytes.ToUpper(s[j:]), doctypeBytes) {
					b.Write(s[written:j])
					b.WriteString("&lt;")
					written = j + 1
				}
			}
		} else if isComment(c.state) && c.delim == delimNone {
			written = i1
		}
		if c.state == stateSpecialElementBody && c.element.name == "script" {
			if err := isJsTemplateBalanced(bytes.NewBuffer(s)); err != nil {
				return context{
					state: stateError,
					err:   errorf(ErrUnbalancedJsTemplate, n, 0, "Mixing template systems can cause security vulnerabilites. Therefore, there can be no safehtml/template insertion points or actions inside an ES6 template, and all ES6 templates must be closed: %v", err.Error()),
				}
			}
		}

		if c.state != c1.state && isComment(c1.state) && c1.delim == delimNone {
			// Preserve the portion between written and the comment start.
			cs := i1 - 2
			if c1.state == stateHTMLCmt {
				// "<!--" instead of "/*" or "//"
				cs -= 2
			}
			b.Write(s[written:cs])
			written = i1
		}
		if i == i1 && c.state == c1.state {
			panic(fmt.Sprintf("infinite loop from %v to %v on %q..%q", c, c1, s[:i], s[i:]))
		}
		c, i = c1, i1
	}

	if written != 0 && c.state != stateError {
		if !isComment(c.state) || c.delim != delimNone {
			b.Write(n.Text[written:])
		}
		e.editTextNode(n, b.Bytes())
	}
	return c
}

// contextAfterText starts in context c, consumes some tokens from the front of
// s, then returns the context after those tokens and the unprocessed suffix.
func contextAfterText(c context, s []byte) (context, int) {
	if c.delim == delimNone {
		c1, i := tSpecialTagEnd(c, s)
		if i == 0 {
			// A special end tag (`</script>`) has been seen and
			// all content preceding it has been consumed.
			return c1, 0
		}
		// Consider all content up to any end tag.
		return transitionFunc[c.state](c, s[:i])
	}

	// We are at the beginning of an attribute value.

	i := bytes.IndexAny(s, delimEnds[c.delim])
	if i == -1 {
		i = len(s)
	}
	if c.delim == delimSpaceOrTagEnd {
		// http://www.w3.org/TR/html5/syntax.html#attribute-value-(unquoted)-state
		// lists the runes below as error characters.
		// Error out because HTML parsers may differ on whether
		// "<a id= onclick=f("     ends inside id's or onclick's value,
		// "<a class=`foo "        ends inside a value,
		// "<a style=font:'Arial'" needs open-quote fixup.
		// IE treats '`' as a quotation character.
		if j := bytes.IndexAny(s[:i], "\"'<=`"); j >= 0 {
			return context{
				state: stateError,
				err:   errorf(ErrBadHTML, nil, 0, "%q in unquoted attr: %q", s[j:j+1], s[:i]),
			}, len(s)
		}
	}
	if i == len(s) {
		c.attr.value += string(s)
		// Remain inside the attribute.
		// Decode the value so non-HTML rules can easily handle
		//     <button onclick="alert(&quot;Hi!&quot;)">
		// without having to entity decode token boundaries.
		for u := []byte(html.UnescapeString(string(s))); len(u) != 0; {
			c1, i1 := transitionFunc[c.state](c, u)
			c, u = c1, u[i1:]
		}
		return c, len(s)
	}

	// On exiting an attribute, we discard all state information
	// except the state, element, scriptType, and linkRel.
	ret := context{
		state:      stateTag,
		element:    c.element,
		scriptType: c.scriptType,
		linkRel:    c.linkRel,
	}
	// Save the script element's type attribute value if we are parsing it for the first time.
	if c.state == stateAttr && c.element.name == "script" && c.attr.name == "type" {
		ret.scriptType = strings.ToLower(string(s[:i]))
	}
	// Save the link element's rel attribute value if we are parsing it for the first time.
	if c.state == stateAttr && c.element.name == "link" && c.attr.name == "rel" {
		ret.linkRel = " " + strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(string(s[:i])))), " ") + " "
	}
	if c.delim != delimSpaceOrTagEnd {
		// Consume any quote.
		i++
	}
	return ret, i
}

// editActionNode records a change to an action pipeline for later commit.
func (e *escaper) editActionNode(n *parse.ActionNode, cmds []string) {
	if _, ok := e.actionNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.actionNodeEdits[n] = cmds
}

// editTemplateNode records a change to a {{template}} callee for later commit.
func (e *escaper) editTemplateNode(n *parse.TemplateNode, callee string) {
	if _, ok := e.templateNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.templateNodeEdits[n] = callee
}

// editTextNode records a change to a text node for later commit.
func (e *escaper) editTextNode(n *parse.TextNode, text []byte) {
	if _, ok := e.textNodeEdits[n]; ok {
		panic(fmt.Sprintf("node %s shared between templates", n))
	}
	e.textNodeEdits[n] = text
}

// commit applies changes to actions and template calls needed to contextually
// autoescape content and adds any derived templates to the set.
func (e *escaper) commit() {
	for name := range e.output {
		e.template(name).Funcs(funcs)
	}
	// Any template from the name space associated with this escaper can be used
	// to add derived templates to the underlying text/template name space.
	tmpl := e.arbitraryTemplate()
	for _, t := range e.derived {
		if _, err := tmpl.text.AddParseTree(t.Name(), t.Tree); err != nil {
			panic("error adding derived template")
		}
	}
	for n, s := range e.actionNodeEdits {
		ensurePipelineContains(n.Pipe, s)
	}
	for n, name := range e.templateNodeEdits {
		n.Name = name
	}
	for n, s := range e.textNodeEdits {
		n.Text = s
	}
	// Reset state that is specific to this commit so that the same changes are
	// not re-applied to the template on subsequent calls to commit.
	e.called = make(map[string]bool)
	e.actionNodeEdits = make(map[*parse.ActionNode][]string)
	e.templateNodeEdits = make(map[*parse.TemplateNode]string)
	e.textNodeEdits = make(map[*parse.TextNode][]byte)
}

// template returns the named template given a mangled template name.
func (e *escaper) template(name string) *template.Template {
	// Any template from the name space associated with this escaper can be used
	// to look up templates in the underlying text/template name space.
	t := e.arbitraryTemplate().text.Lookup(name)
	if t == nil {
		t = e.derived[name]
	}
	return t
}

// arbitraryTemplate returns an arbitrary template from the name space
// associated with e and panics if no templates are found.
func (e *escaper) arbitraryTemplate() *Template {
	for _, t := range e.ns.set {
		return t
	}
	panic("no templates in name space")
}

var (
	errorType       = reflect.TypeOf((*error)(nil)).Elem()
	fmtStringerType = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()
)

// indirectToStringerOrError returns the value, after dereferencing as many times
// as necessary to reach the base type (or nil) or an implementation of fmt.Stringer
// or error,
func indirectToStringerOrError(a interface{}) interface{} {
	if a == nil {
		return nil
	}
	v := reflect.ValueOf(a)
	for !v.Type().Implements(fmtStringerType) && !v.Type().Implements(errorType) && v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	return v.Interface()
}

var (
	jsTemplateSeparator = []byte("`")
	jsTemplateExprStart = []byte("${")
	jsTemplateExprEnd   = []byte("}")
)

// Determine if a string has unbalanced (open) JS templates.
func isJsTemplateBalanced(s *bytes.Buffer) error {
	for {
		index := bytes.Index(s.Bytes(), jsTemplateSeparator)
		if index == -1 {
			return nil
		}
		s.Next(index + 1)
		err := consumeJsTemplate(s)
		if err != nil {
			return err
		}
	}
}

// s is a JS template string (without the opening `); this function consumes s up to
// the matching closing `.
func consumeJsTemplate(s *bytes.Buffer) error {
	for {
		templateEnd := bytes.Index(s.Bytes(), jsTemplateSeparator)
		exprStart := bytes.Index(s.Bytes(), jsTemplateExprStart)
		if templateEnd == -1 {
			return fmt.Errorf("Missing closing ` in JS template")
		}
		if exprStart != -1 && exprStart < templateEnd {
			err := consumeJsTemplateExpr(s)
			if err != nil {
				return err
			}
			return consumeJsTemplate(s)
		} else {
			// The template expression occurs after this template, e.g. "`foo``bar${test}`".
			s.Next(templateEnd + 1)
			return nil
		}
	}
}

// s is a Js Template expression (starting with "${"). This function consumes up to and including the matching closing "}".
func consumeJsTemplateExpr(s *bytes.Buffer) error {
	for {
		exprEnd := bytes.Index(s.Bytes(), jsTemplateExprEnd)
		if exprEnd == -1 {
			// Template expression isn't closed
			return fmt.Errorf("Missing closing } in JS template")
		}
		nestedTemplateStart := bytes.Index(s.Bytes(), jsTemplateSeparator)
		if nestedTemplateStart != -1 && nestedTemplateStart < exprEnd {
			s.Next(nestedTemplateStart + 1)
			err := consumeJsTemplate(s)
			if err != nil {
				return err
			}
			return consumeJsTemplateExpr(s)
		} else {
			s.Next(exprEnd + 1)
			return nil
		}
	}
}
