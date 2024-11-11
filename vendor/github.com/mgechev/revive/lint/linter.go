package lint

import (
	"bufio"
	"bytes"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	goversion "github.com/hashicorp/go-version"
	"golang.org/x/mod/modfile"
)

// ReadFile defines an abstraction for reading files.
type ReadFile func(path string) (result []byte, err error)

type disabledIntervalsMap = map[string][]DisabledInterval

// Linter is used for linting set of files.
type Linter struct {
	reader         ReadFile
	fileReadTokens chan struct{}
}

// New creates a new Linter
func New(reader ReadFile, maxOpenFiles int) Linter {
	var fileReadTokens chan struct{}
	if maxOpenFiles > 0 {
		fileReadTokens = make(chan struct{}, maxOpenFiles)
	}
	return Linter{
		reader:         reader,
		fileReadTokens: fileReadTokens,
	}
}

func (l Linter) readFile(path string) (result []byte, err error) {
	if l.fileReadTokens != nil {
		// "take" a token by writing to the channel.
		// It will block if no more space in the channel's buffer
		l.fileReadTokens <- struct{}{}
		defer func() {
			// "free" a token by reading from the channel
			<-l.fileReadTokens
		}()
	}

	return l.reader(path)
}

var (
	genHdr           = []byte("// Code generated ")
	genFtr           = []byte(" DO NOT EDIT.")
	defaultGoVersion = goversion.Must(goversion.NewVersion("1.0"))
)

// Lint lints a set of files with the specified rule.
func (l *Linter) Lint(packages [][]string, ruleSet []Rule, config Config) (<-chan Failure, error) {
	failures := make(chan Failure)

	perModVersions := make(map[string]*goversion.Version)
	perPkgVersions := make([]*goversion.Version, len(packages))
	for n, files := range packages {
		if len(files) == 0 {
			continue
		}
		if config.GoVersion != nil {
			perPkgVersions[n] = config.GoVersion
			continue
		}

		dir, err := filepath.Abs(filepath.Dir(files[0]))
		if err != nil {
			return nil, err
		}

		alreadyKnownMod := false
		for d, v := range perModVersions {
			if strings.HasPrefix(dir, d) {
				perPkgVersions[n] = v
				alreadyKnownMod = true
				break
			}
		}
		if alreadyKnownMod {
			continue
		}

		d, v, err := detectGoMod(dir)
		if err != nil {
			// No luck finding the go.mod file thus set the default Go version
			v = defaultGoVersion
			d = dir
		}
		perModVersions[d] = v
		perPkgVersions[n] = v
	}

	var wg sync.WaitGroup
	for n := range packages {
		wg.Add(1)
		go func(pkg []string, gover *goversion.Version) {
			if err := l.lintPackage(pkg, gover, ruleSet, config, failures); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer wg.Done()
		}(packages[n], perPkgVersions[n])
	}

	go func() {
		wg.Wait()
		close(failures)
	}()

	return failures, nil
}

func (l *Linter) lintPackage(filenames []string, gover *goversion.Version, ruleSet []Rule, config Config, failures chan Failure) error {
	if len(filenames) == 0 {
		return nil
	}

	pkg := &Package{
		fset:      token.NewFileSet(),
		files:     map[string]*File{},
		goVersion: gover,
	}
	for _, filename := range filenames {
		content, err := l.readFile(filename)
		if err != nil {
			return err
		}
		if !config.IgnoreGeneratedHeader && isGenerated(content) {
			continue
		}

		file, err := NewFile(filename, content, pkg)
		if err != nil {
			addInvalidFileFailure(filename, err.Error(), failures)
			continue
		}
		pkg.files[filename] = file
	}

	if len(pkg.files) == 0 {
		return nil
	}

	pkg.lint(ruleSet, config, failures)

	return nil
}

func detectGoMod(dir string) (rootDir string, ver *goversion.Version, err error) {
	modFileName, err := retrieveModFile(dir)
	if err != nil {
		return "", nil, fmt.Errorf("%q doesn't seem to be part of a Go module", dir)
	}

	mod, err := os.ReadFile(modFileName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read %q, got %v", modFileName, err)
	}

	modAst, err := modfile.ParseLax(modFileName, mod, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse %q, got %v", modFileName, err)
	}

	ver, err = goversion.NewVersion(modAst.Go.Version)
	return filepath.Dir(modFileName), ver, err
}

func retrieveModFile(dir string) (string, error) {
	const lookingForFile = "go.mod"
	for {
		if dir == "." || dir == "/" {
			return "", fmt.Errorf("did not found %q file", lookingForFile)
		}

		lookingForFilePath := filepath.Join(dir, lookingForFile)
		info, err := os.Stat(lookingForFilePath)
		if err != nil || info.IsDir() {
			// lets check the parent dir
			dir = filepath.Dir(dir)
			continue
		}

		return lookingForFilePath, nil
	}
}

// isGenerated reports whether the source file is generated code
// according the rules from https://golang.org/s/generatedcode.
// This is inherited from the original go lint.
func isGenerated(src []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(src))
	for sc.Scan() {
		b := sc.Bytes()
		if bytes.HasPrefix(b, genHdr) && bytes.HasSuffix(b, genFtr) && len(b) >= len(genHdr)+len(genFtr) {
			return true
		}
	}
	return false
}

// addInvalidFileFailure adds a failure for an invalid formatted file
func addInvalidFileFailure(filename, errStr string, failures chan Failure) {
	position := getPositionInvalidFile(filename, errStr)
	failures <- Failure{
		Confidence: 1,
		Failure:    fmt.Sprintf("invalid file %s: %v", filename, errStr),
		Category:   "validity",
		Position:   position,
	}
}

// errPosRegexp matches with an NewFile error message
// i.e. :  corrupted.go:10:4: expected '}', found 'EOF
// first group matches the line and the second group, the column
var errPosRegexp = regexp.MustCompile(`.*:(\d*):(\d*):.*$`)

// getPositionInvalidFile gets the position of the error in an invalid file
func getPositionInvalidFile(filename, s string) FailurePosition {
	pos := errPosRegexp.FindStringSubmatch(s)
	if len(pos) < 3 {
		return FailurePosition{}
	}
	line, err := strconv.Atoi(pos[1])
	if err != nil {
		return FailurePosition{}
	}
	column, err := strconv.Atoi(pos[2])
	if err != nil {
		return FailurePosition{}
	}

	return FailurePosition{
		Start: token.Position{
			Filename: filename,
			Line:     line,
			Column:   column,
		},
	}
}
