// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"sync"
	"text/template"
	"text/template/parse"

	"log"
	"github.com/google/safehtml"
	"github.com/google/safehtml/uncheckedconversions"
)

// Template is a specialized Template from "text/template" that produces a safe
// HTML document fragment.
type Template struct {
	// Sticky error if escaping fails, or errEscapeOK if succeeded.
	escapeErr error
	// We could embed the text/template field, but it's safer not to because
	// we need to keep our version of the name space and the underlying
	// template's in sync.
	text *template.Template
	// The underlying template's parse tree, updated to be HTML-safe.
	Tree       *parse.Tree
	*nameSpace // common to all associated templates
}

// errEscapeOK is a sentinel value used to indicate valid escaping.
var errEscapeOK = fmt.Errorf("template escaped correctly")

// nameSpace is the data structure shared by all templates in an association.
type nameSpace struct {
	mu      sync.Mutex
	set     map[string]*Template
	escaped bool
	// cspCompatible indicates whether inline event handlers and
	// javascript: URIs are disallowed in templates in this namespace.
	cspCompatible bool
	esc           escaper
}

// Templates returns a slice of the templates associated with t, including t
// itself.
func (t *Template) Templates() []*Template {
	ns := t.nameSpace
	ns.mu.Lock()
	defer ns.mu.Unlock()
	// Return a slice so we don't expose the map.
	m := make([]*Template, 0, len(ns.set))
	for _, v := range ns.set {
		m = append(m, v)
	}
	return m
}

// Option sets options for the template. Options are described by
// strings, either a simple string or "key=value". There can be at
// most one equals sign in an option string. If the option string
// is unrecognized or otherwise invalid, Option panics.
//
// Known options:
//
// missingkey: Control the behavior during execution if a map is
// indexed with a key that is not present in the map.
//	"missingkey=default" or "missingkey=invalid"
//		The default behavior: Do nothing and continue execution.
//		If printed, the result of the index operation is the string
//		"<no value>".
//	"missingkey=zero"
//		The operation returns the zero value for the map type's element.
//	"missingkey=error"
//		Execution stops immediately with an error.
//
func (t *Template) Option(opt ...string) *Template {
	t.text.Option(opt...)
	return t
}

// checkCanParse checks whether it is OK to parse templates.
// If not, it returns an error.
func (t *Template) checkCanParse() error {
	if t == nil {
		return nil
	}
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	if t.nameSpace.escaped {
		return fmt.Errorf("html/template: cannot Parse after Execute")
	}
	return nil
}

// escape escapes all associated templates.
func (t *Template) escape() error {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	t.nameSpace.escaped = true
	if t.escapeErr == nil {
		if t.Tree == nil {
			return fmt.Errorf("template: %q is an incomplete or empty template", t.Name())
		}
		if err := escapeTemplate(t, t.text.Root, t.Name()); err != nil {
			return err
		}
	} else if t.escapeErr != errEscapeOK {
		return t.escapeErr
	}
	return nil
}

// Execute applies a parsed template to the specified data object,
// writing the output to wr.
// If an error occurs executing the template or writing its output,
// execution stops, but partial results may already have been written to
// the output writer.
// A template may be executed safely in parallel, although if parallel
// executions share a Writer the output may be interleaved.
func (t *Template) Execute(wr io.Writer, data interface{}) error {
	if err := t.escape(); err != nil {
		return err
	}
	return t.text.Execute(wr, data)
}

// ExecuteToHTML applies a parsed template to the specified data object,
// returning the output as a safehtml.HTML value.
// A template may be executed safely in parallel.
func (t *Template) ExecuteToHTML(data interface{}) (safehtml.HTML, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return safehtml.HTML{}, err
	}
	return uncheckedconversions.HTMLFromStringKnownToSatisfyTypeContract(buf.String()), nil
}

// MustParseAndExecuteToHTML is a helper that returns the safehtml.HTML value produced
// by parsing text as a template body and executing it with no data. Any errors
// encountered parsing or executing the template are fatal. This function is intended
// to produce safehtml.HTML values from static HTML snippets such as
//
//	html := MustParseAndExecuteToHTML("<b>Important</b>")
//
// To guarantee that the template body is never controlled by an attacker, text
// must be an untyped string constant, which is always under programmer control.
func MustParseAndExecuteToHTML(text stringConstant) safehtml.HTML {
	t, err := New("").Parse(text)
	if err != nil {
		log.Fatal(err)
	}
	html, err := t.ExecuteToHTML(nil)
	if err != nil {
		log.Fatal(err)
	}
	return html
}

// ExecuteTemplate applies the template associated with t that has the given
// name to the specified data object and writes the output to wr.
// If an error occurs executing the template or writing its output,
// execution stops, but partial results may already have been written to
// the output writer.
// A template may be executed safely in parallel, although if parallel
// executions share a Writer the output may be interleaved.
func (t *Template) ExecuteTemplate(wr io.Writer, name string, data interface{}) error {
	tmpl, err := t.lookupAndEscapeTemplate(name)
	if err != nil {
		return err
	}
	return tmpl.text.Execute(wr, data)
}

// ExecuteTemplateToHTML applies the template associated with t that has
// the given name to the specified data object and returns the output as
// a safehtml.HTML value.
// A template may be executed safely in parallel.
func (t *Template) ExecuteTemplateToHTML(name string, data interface{}) (safehtml.HTML, error) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		return safehtml.HTML{}, err
	}
	return uncheckedconversions.HTMLFromStringKnownToSatisfyTypeContract(buf.String()), nil
}

// lookupAndEscapeTemplate guarantees that the template with the given name
// is escaped, or returns an error if it cannot be. It returns the named
// template.
func (t *Template) lookupAndEscapeTemplate(name string) (tmpl *Template, err error) {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	t.nameSpace.escaped = true
	tmpl = t.set[name]
	if tmpl == nil {
		return nil, fmt.Errorf("html/template: %q is undefined", name)
	}
	if tmpl.escapeErr != nil && tmpl.escapeErr != errEscapeOK {
		return nil, tmpl.escapeErr
	}
	if tmpl.text.Tree == nil || tmpl.text.Root == nil {
		return nil, fmt.Errorf("html/template: %q is an incomplete template", name)
	}
	if t.text.Lookup(name) == nil {
		panic("html/template internal error: template escaping out of sync")
	}
	if tmpl.escapeErr == nil {
		err = escapeTemplate(tmpl, tmpl.text.Root, name)
	}
	return tmpl, err
}

// DefinedTemplates returns a string listing the defined templates,
// prefixed by the string "; defined templates are: ". If there are none,
// it returns the empty string. Used to generate an error message.
func (t *Template) DefinedTemplates() string {
	return t.text.DefinedTemplates()
}

// Parse parses text as a template body for t.
// Named template definitions ({{define ...}} or {{block ...}} statements) in text
// define additional templates associated with t and are removed from the
// definition of t itself.
//
// Templates can be redefined in successive calls to Parse,
// before the first use of Execute on t or any associated template.
// A template definition with a body containing only white space and comments
// is considered empty and will not replace an existing template's body.
// This allows using Parse to add new named template definitions without
// overwriting the main template body.
//
// To guarantee that the template body is never controlled by an attacker, text
// must be an untyped string constant, which is always under programmer control.
func (t *Template) Parse(text stringConstant) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}

	ret, err := t.text.Parse(string(text))
	if err != nil {
		return nil, err
	}

	// In general, all the named templates might have changed underfoot.
	// Regardless, some new ones may have been defined.
	// The template.Template set has been updated; update ours.
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	for _, v := range ret.Templates() {
		name := v.Name()
		tmpl := t.set[name]
		if tmpl == nil {
			tmpl = t.new(name)
		}
		tmpl.text = v
		tmpl.Tree = v.Tree
	}
	return t, nil
}

// ParseFromTrustedTemplate parses tmpl as a template body for t.
// Named template definitions ({{define ...}} or {{block ...}} statements) in text
// define additional templates associated with t and are removed from the
// definition of t itself.
//
// Templates can be redefined in successive calls to ParseFromTrustedTemplate,
// before the first use of Execute on t or any associated template.
// A template definition with a body containing only white space and comments
// is considered empty and will not replace an existing template's body.
// This allows using ParseFromTrustedTemplate to add new named template definitions without
// overwriting the main template body.
//
// To guarantee that the template body is never controlled by an attacker, tmpl
// is a TrustedTemplate, which is always under programmer control.
func (t *Template) ParseFromTrustedTemplate(tmpl TrustedTemplate) (*Template, error) {
	return t.Parse(stringConstant(tmpl.String()))
}

// Clone returns a duplicate of the template, including all associated
// templates. The actual representation is not copied, but the name space of
// associated templates is, so further calls to Parse in the copy will add
// templates to the copy but not to the original. Clone can be used to prepare
// common templates and use them with variant definitions for other templates
// by adding the variants after the clone is made.
//
// It returns an error if t has already been executed.
func (t *Template) Clone() (*Template, error) {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	if t.escapeErr != nil {
		return nil, fmt.Errorf("html/template: cannot Clone %q after it has executed", t.Name())
	}
	textClone, err := t.text.Clone()
	if err != nil {
		return nil, err
	}
	ns := &nameSpace{set: make(map[string]*Template)}
	ns.esc = makeEscaper(ns)
	ret := &Template{
		nil,
		textClone,
		textClone.Tree,
		ns,
	}
	ret.set[ret.Name()] = ret
	for _, x := range textClone.Templates() {
		name := x.Name()
		src := t.set[name]
		if src == nil || src.escapeErr != nil {
			return nil, fmt.Errorf("html/template: cannot Clone %q after it has executed", t.Name())
		}
		x.Tree = x.Tree.Copy()
		ret.set[name] = &Template{
			nil,
			x,
			x.Tree,
			ret.nameSpace,
		}
	}
	// Return the template associated with the name of this template.
	return ret.set[ret.Name()], nil
}

// New allocates a new HTML template with the given name.
func New(name string) *Template {
	ns := &nameSpace{set: make(map[string]*Template)}
	ns.esc = makeEscaper(ns)
	tmpl := &Template{
		nil,
		template.New(name),
		nil,
		ns,
	}
	tmpl.set[name] = tmpl
	return tmpl
}

// New allocates a new HTML template associated with the given one
// and with the same delimiters. The association, which is transitive,
// allows one template to invoke another with a {{template}} action.
//
// If a template with the given name already exists, the new HTML template
// will replace it. The existing template will be reset and disassociated with
// t.
func (t *Template) New(name string) *Template {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	return t.new(name)
}

// new is the implementation of New, without the lock.
func (t *Template) new(name string) *Template {
	tmpl := &Template{
		nil,
		t.text.New(name),
		nil,
		t.nameSpace,
	}
	if existing, ok := tmpl.set[name]; ok {
		emptyTmpl := New(existing.Name())
		*existing = *emptyTmpl
	}
	tmpl.set[name] = tmpl
	return tmpl
}

// Name returns the name of the template.
func (t *Template) Name() string {
	return t.text.Name()
}

// FuncMap is the type of the map defining the mapping from names to
// functions. Each function must have either a single return value, or two
// return values of which the second has type error. In that case, if the
// second (error) argument evaluates to non-nil during execution, execution
// terminates and Execute returns that error. FuncMap has the same base type
// as FuncMap in "text/template", copied here so clients need not import
// "text/template".
type FuncMap map[string]interface{}

// Funcs adds the elements of the argument map to the template's function map.
// It must be called before the template is parsed.
// It panics if a value in the map is not a function with appropriate return
// type. However, it is legal to overwrite elements of the map. The return
// value is the template, so calls can be chained.
func (t *Template) Funcs(funcMap FuncMap) *Template {
	t.text.Funcs(template.FuncMap(funcMap))
	return t
}

// CSPCompatible causes this template to check template text for
// Content Security Policy (CSP) compatibility. The template will return errors
// at execution time if inline event handler attribute names or javascript:
// URIs are found in template text.
//
// For example, the following templates will cause errors:
//     <span onclick="doThings();">A thing.</span> // inline event handler "onclick"
//     <a href="javascript:linkClicked()">foo</a>  // javascript: URI present
func (t *Template) CSPCompatible() *Template {
	t.nameSpace.mu.Lock()
	t.nameSpace.cspCompatible = true
	t.nameSpace.mu.Unlock()
	return t
}

// Delims sets the action delimiters to the specified strings, to be used in
// subsequent calls to Parse, ParseFiles, or ParseGlob. Nested template
// definitions will inherit the settings. An empty delimiter stands for the
// corresponding default: {{ or }}.
// The return value is the template, so calls can be chained.
func (t *Template) Delims(left, right string) *Template {
	t.text.Delims(left, right)
	return t
}

// Lookup returns the template with the given name that is associated with t,
// or nil if there is no such template.
func (t *Template) Lookup(name string) *Template {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	return t.set[name]
}

// Must is a helper that wraps a call to a function returning (*Template, error)
// and panics if the error is non-nil. It is intended for use in variable initializations
// such as
//	var t = template.Must(template.New("name").Parse("html"))
func Must(t *Template, err error) *Template {
	if err != nil {
		panic(err)
	}
	return t
}

// stringConstant is an unexported string type. Users of this package cannot
// create values of this type except by passing an untyped string constant to
// functions which expect a stringConstant. This type must be used only in
// function and method parameters.
type stringConstant string

func stringConstantsToStrings(strs []stringConstant) []string {
	ret := make([]string, 0, len(strs))
	for _, s := range strs {
		ret = append(ret, string(s))
	}
	return ret
}

// ParseFiles creates a new Template and parses the template definitions from
// the named files. The returned template's name will have the (base) name and
// (parsed) contents of the first file. There must be at least one file.
// If an error occurs, parsing stops and the returned *Template is nil.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
// For instance, ParseFiles("a/foo", "b/foo") stores "b/foo" as the template
// named "foo", while "a/foo" is unavailable.
//
// To guarantee that filepaths, and thus template bodies, are never controlled by
// an attacker, filenames must be untyped string constants, which are always under
// programmer control.
func ParseFiles(filenames ...stringConstant) (*Template, error) {
	return parseFiles(nil, readFileOS, stringConstantsToStrings(filenames)...)
}

// ParseFilesFromTrustedSources creates a new Template and parses the template definitions from
// the named files. The returned template's name will have the (base) name and
// (parsed) contents of the first file. There must be at least one file.
// If an error occurs, parsing stops and the returned *Template is nil.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
// For instance, ParseFiles("a/foo", "b/foo") stores "b/foo" as the template
// named "foo", while "a/foo" is unavailable.
//
// To guarantee that filepaths, and thus template bodies, are never controlled by
// an attacker, filenames must be trusted sources, which are always under programmer
// or application control.
func ParseFilesFromTrustedSources(filenames ...TrustedSource) (*Template, error) {
	return parseFiles(nil, readFileOS, trustedSourcesToStrings(filenames)...)
}

// ParseFiles parses the named files and associates the resulting templates with
// t. If an error occurs, parsing stops and the returned template is nil;
// otherwise it is t. There must be at least one file.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseFiles returns an error if t or any associated template has already been executed.
//
// To guarantee that filepaths, and thus template bodies, are never controlled by
// an attacker, filenames must be untyped string constants, which are always under
// programmer control.
func (t *Template) ParseFiles(filenames ...stringConstant) (*Template, error) {
	return parseFiles(t, readFileOS, stringConstantsToStrings(filenames)...)
}

// ParseFilesFromTrustedSources parses the named files and associates the resulting templates with
// t. If an error occurs, parsing stops and the returned template is nil;
// otherwise it is t. There must be at least one file.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseFilesFromTrustedSources returns an error if t or any associated template has already been executed.
//
// To guarantee that filepaths, and thus template bodies, are never controlled by
// an attacker, filenames must be trusted sources, which are always under programmer
// or application control.
func (t *Template) ParseFilesFromTrustedSources(filenames ...TrustedSource) (*Template, error) {
	return parseFiles(t, readFileOS, trustedSourcesToStrings(filenames)...)
}

// parseFiles is the helper for the method and function. If the argument
// template is nil, it is created from the first file.
// readFile takes a filename and returns the file's basename and contents.
func parseFiles(t *Template, readFile func(string) (string, []byte, error), filenames ...string) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}

	if len(filenames) == 0 {
		// Not really a problem, but be consistent.
		return nil, fmt.Errorf("html/template: no files named in call to ParseFiles")
	}
	for _, filename := range filenames {
		name, b, err := readFile(filename)
		if err != nil {
			return nil, err
		}
		s := stringConstant(b)
		// First template becomes return value if not already defined,
		// and we use that one for subsequent New calls to associate
		// all the templates together. Also, if this file has the same name
		// as t, this file becomes the contents of t, so
		//  t, err := New(name).Funcs(xxx).ParseFiles(name)
		// works. Otherwise we create a new template associated with t.
		var tmpl *Template
		if t == nil {
			t = New(name)
		}
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		_, err = tmpl.Parse(s)
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// Copied with minor changes from
// https://go.googlesource.com/go/+/refs/tags/go1.17.1/src/text/template/helper.go.
func readFileOS(file string) (string, []byte, error) {
	name := filepath.Base(file)
	b, err := ioutil.ReadFile(file)
	return name, b, err
}

// ParseGlob creates a new Template and parses the template definitions from the
// files identified by the pattern, which must match at least one file. The
// returned template will have the (base) name and (parsed) contents of the
// first file matched by the pattern. ParseGlob is equivalent to calling
// ParseFiles with the list of files matched by the pattern.
//
// To guarantee that the pattern, and thus the template bodies, is never controlled by
// an attacker, pattern must be an untyped string constant, which is always under
// programmer control.
func ParseGlob(pattern stringConstant) (*Template, error) {
	return parseGlob(nil, string(pattern))
}

// ParseGlobFromTrustedSource creates a new Template and parses the template definitions from the
// files identified by the pattern, which must match at least one file. The
// returned template will have the (base) name and (parsed) contents of the
// first file matched by the pattern. ParseGlobFromTrustedSource is equivalent to calling
// ParseFilesFromTrustedSources with the list of files matched by the pattern.
//
// To guarantee that the pattern, and thus the template bodies, is never controlled by
// an attacker, pattern must be a trusted source, which is always under programmer or
// application control.
func ParseGlobFromTrustedSource(pattern TrustedSource) (*Template, error) {
	return parseGlob(nil, pattern.String())
}

// ParseGlob parses the template definitions in the files identified by the
// pattern and associates the resulting templates with t. The pattern is
// processed by filepath.Glob and must match at least one file. ParseGlob is
// equivalent to calling t.ParseFiles with the list of files matched by the
// pattern.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseGlob returns an error if t or any associated template has already been executed.
//
// To guarantee that the pattern, and thus the template bodies, is never controlled by
// an attacker, pattern must be an untyped string constant, which is always under
// programmer control.
func (t *Template) ParseGlob(pattern stringConstant) (*Template, error) {
	return parseGlob(t, string(pattern))
}

// ParseGlobFromTrustedSource parses the template definitions in the files identified by the
// pattern and associates the resulting templates with t. The pattern is
// processed by filepath.Glob and must match at least one file. ParseGlob is
// equivalent to calling t.ParseFiles with the list of files matched by the
// pattern.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseGlobFromTrustedSource returns an error if t or any associated template has already been executed.
//
// To guarantee that the pattern, and thus the template bodies, is never controlled by
// an attacker, pattern must be a trusted source, which is always under programmer or
// application control.
func (t *Template) ParseGlobFromTrustedSource(pattern TrustedSource) (*Template, error) {
	return parseGlob(t, pattern.String())
}

// parseGlob is the implementation of the function and method ParseGlob.
func parseGlob(t *Template, pattern string) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}
	filenames, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(filenames) == 0 {
		return nil, fmt.Errorf("html/template: pattern matches no files: %#q", pattern)
	}
	return parseFiles(t, readFileOS, filenames...)
}

// IsTrue reports whether the value is 'true', in the sense of not the zero of its type,
// and whether the value has a meaningful truth value. This is the definition of
// truth used by if and other such actions.
func IsTrue(val interface{}) (truth, ok bool) {
	return template.IsTrue(val)
}
