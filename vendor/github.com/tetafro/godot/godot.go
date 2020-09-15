// Package godot checks if all top-level comments contain a period at the
// end of the last sentence if needed.
package godot

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	// noPeriodMessage is an error message to return.
	noPeriodMessage = "Top level comment should end in a period"
	// topLevelColumn is just the most left column of the file.
	topLevelColumn = 1
	// topLevelGroupColumn is the most left column inside a group declaration
	// on the top level.
	topLevelGroupColumn = 2
)

// Settings contains linter settings.
type Settings struct {
	// Check all top-level comments, not only declarations
	CheckAll bool
}

// Issue contains a description of linting error and a possible replacement.
type Issue struct {
	Pos         token.Position
	Message     string
	Replacement string
}

// position is an position inside a comment (might be multiline comment).
type position struct {
	line   int
	column int
}

var (
	// List of valid last characters.
	lastChars = []string{".", "?", "!"}

	// Special tags in comments like "// nolint:", or "// +k8s:".
	tags = regexp.MustCompile(`^\+?[a-z0-9]+:`)

	// Special hashtags in comments like "#nosec".
	hashtags = regexp.MustCompile("^#[a-z]+ ")

	// URL at the end of the line.
	endURL = regexp.MustCompile(`[a-z]+://[^\s]+$`)
)

// Run runs this linter on the provided code.
func Run(file *ast.File, fset *token.FileSet, settings Settings) []Issue {
	issues := checkBlocks(file, fset)

	// Check all top-level comments
	if settings.CheckAll {
		issues = append(issues, checkTopLevel(file, fset)...)
		sortIssues(issues)
		return issues
	}

	// Check only declaration comments
	issues = append(issues, checkDeclarations(file, fset)...)
	sortIssues(issues)
	return issues
}

// Fix fixes all issues and return new version of file content.
func Fix(path string, file *ast.File, fset *token.FileSet, settings Settings) ([]byte, error) {
	// Read file
	content, err := ioutil.ReadFile(path) // nolint: gosec
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	if len(content) == 0 {
		return nil, nil
	}

	issues := Run(file, fset, settings)

	// slice -> map
	m := map[int]Issue{}
	for _, iss := range issues {
		m[iss.Pos.Line] = iss
	}

	// Replace lines from issues
	fixed := make([]byte, 0, len(content))
	for i, line := range strings.Split(string(content), "\n") {
		newline := line
		if iss, ok := m[i+1]; ok {
			newline = iss.Replacement
		}
		fixed = append(fixed, []byte(newline+"\n")...)
	}
	fixed = fixed[:len(fixed)-1] // trim last "\n"

	return fixed, nil
}

// Replace rewrites original file with it's fixed version.
func Replace(path string, file *ast.File, fset *token.FileSet, settings Settings) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("check file: %v", err)
	}
	mode := info.Mode()

	fixed, err := Fix(path, file, fset, settings)
	if err != nil {
		return fmt.Errorf("fix issues: %v", err)
	}

	if err := ioutil.WriteFile(path, fixed, mode); err != nil {
		return fmt.Errorf("write file: %v", err)
	}
	return nil
}

// sortIssues sorts by filename, line and column.
func sortIssues(iss []Issue) {
	sort.Slice(iss, func(i, j int) bool {
		if iss[i].Pos.Filename != iss[j].Pos.Filename {
			return iss[i].Pos.Filename < iss[j].Pos.Filename
		}
		if iss[i].Pos.Line != iss[j].Pos.Line {
			return iss[i].Pos.Line < iss[j].Pos.Line
		}
		return iss[i].Pos.Column < iss[j].Pos.Column
	})
}

// checkTopLevel checks all top-level comments.
func checkTopLevel(file *ast.File, fset *token.FileSet) (issues []Issue) {
	for _, group := range file.Comments {
		if iss, ok := check(fset, group, topLevelColumn); !ok {
			issues = append(issues, iss)
		}
	}
	return issues
}

// checkDeclarations checks top level declaration comments.
func checkDeclarations(file *ast.File, fset *token.FileSet) (issues []Issue) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if iss, ok := check(fset, d.Doc, topLevelColumn); !ok {
				issues = append(issues, iss)
			}
		case *ast.FuncDecl:
			if iss, ok := check(fset, d.Doc, topLevelColumn); !ok {
				issues = append(issues, iss)
			}
		}
	}
	return issues
}

// checkBlocks checks comments inside top level blocks (var (...), const (...), etc).
func checkBlocks(file *ast.File, fset *token.FileSet) (issues []Issue) {
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		// No parenthesis == no block
		if d.Lparen == 0 {
			continue
		}
		for _, group := range file.Comments {
			// Skip comments outside this block
			if d.Lparen > group.Pos() || group.Pos() > d.Rparen {
				continue
			}
			// Skip comments that are not top-level for this block
			if fset.Position(group.Pos()).Column != topLevelGroupColumn {
				continue
			}
			if iss, ok := check(fset, group, topLevelGroupColumn); !ok {
				issues = append(issues, iss)
			}
		}
	}
	return issues
}

func check(fset *token.FileSet, group *ast.CommentGroup, level int) (iss Issue, ok bool) {
	if group == nil || len(group.List) == 0 {
		return Issue{}, true
	}

	// Check only top-level comments
	if fset.Position(group.Pos()).Column > level {
		return Issue{}, true
	}

	// Get last element from comment group - it can be either
	// last (or single) line for "//"-comment, or multiline string
	// for "/*"-comment
	last := group.List[len(group.List)-1]

	p, ok := checkComment(last.Text)
	if ok {
		return Issue{}, true
	}

	pos := fset.Position(last.Slash)
	pos.Line += p.line
	pos.Column = p.column + level - 1

	indent := strings.Repeat("\t", level-1)

	iss = Issue{
		Pos:         pos,
		Message:     noPeriodMessage,
		Replacement: indent + makeReplacement(last.Text, p),
	}
	return iss, false
}

func checkComment(comment string) (pos position, ok bool) {
	// Check last line of "//"-comment
	if strings.HasPrefix(comment, "//") {
		pos.column = len([]rune(comment)) // runes for non-latin chars
		comment = strings.TrimPrefix(comment, "//")
		if checkLastChar(comment) {
			return position{}, true
		}
		return pos, false
	}

	// Skip cgo code blocks
	// TODO: Find a better way to detect cgo code
	if strings.Contains(comment, "#include") || strings.Contains(comment, "#define") {
		return position{}, true
	}

	// Check last non-empty line in multiline "/*"-comment block
	lines := strings.Split(comment, "\n")
	var i int
	for i = len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s == "*/" || s == "" {
			continue
		}
		break
	}
	pos.line = i
	comment = lines[i]
	comment = strings.TrimSuffix(comment, "*/")
	comment = strings.TrimRight(comment, " ")
	// Get position of the last non-space char in comment line, use runes
	// in case of non-latin chars
	pos.column = len([]rune(comment))
	comment = strings.TrimPrefix(comment, "/*")

	if checkLastChar(comment) {
		return position{}, true
	}
	return pos, false
}

func checkLastChar(s string) bool {
	// Don't check comments starting with space indentation - they may
	// contain code examples, which shouldn't end with period
	if strings.HasPrefix(s, "  ") || strings.HasPrefix(s, " \t") || strings.HasPrefix(s, "\t") {
		return true
	}
	// Skip cgo export tags: https://golang.org/cmd/cgo/#hdr-C_references_to_Go
	if strings.HasPrefix(s, "export") {
		return true
	}
	s = strings.TrimSpace(s)
	if tags.MatchString(s) ||
		hashtags.MatchString(s) ||
		endURL.MatchString(s) ||
		strings.HasPrefix(s, "+build") {
		return true
	}
	// Don't check empty lines
	if s == "" {
		return true
	}
	// Trim parenthesis for cases when the whole sentence is inside parenthesis
	s = strings.TrimRight(s, ")")
	for _, ch := range lastChars {
		if string(s[len(s)-1]) == ch {
			return true
		}
	}
	return false
}

// makeReplacement basically just inserts a period into comment on
// the given position.
func makeReplacement(s string, pos position) string {
	lines := strings.Split(s, "\n")
	if len(lines) < pos.line {
		// This should never happen
		return s
	}
	line := []rune(lines[pos.line])
	if len(line) < pos.column {
		// This should never happen
		return s
	}
	// Insert a period
	newline := append(
		line[:pos.column],
		append([]rune{'.'}, line[pos.column:]...)...,
	)
	return string(newline)
}
