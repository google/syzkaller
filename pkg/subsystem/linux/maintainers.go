// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bufio"
	"fmt"
	"io"
	"net/mail"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/syzkaller/pkg/subsystem"
)

// maintainersRecord represents a single raw record in the MAINTAINERS file.
type maintainersRecord struct {
	name            string
	includePatterns []string
	excludePatterns []string
	regexps         []string
	lists           []string
	maintainers     []string
	trees           []string
}

func parseLinuxMaintainers(content io.Reader) ([]*maintainersRecord, error) {
	scanner := bufio.NewScanner(content)
	// First skip the headers.
	for scanner.Scan() {
		line := scanner.Text()
		if line == "Maintainers List" {
			// Also skip ------.
			scanner.Scan()
			break
		}
	}
	ml := &maintainersLexer{scanner: scanner}
	ret := []*maintainersRecord{}
loop:
	for {
		item := ml.next()
		switch v := item.(type) {
		case recordTitle:
			// The new subsystem begins.
			ret = append(ret, &maintainersRecord{name: string(v)})
		case recordProperty:
			if len(ret) == 0 {
				return nil, fmt.Errorf("line %d: property without subsystem", ml.currentLine)
			}
			err := applyProperty(ret[len(ret)-1], &v)
			if err != nil {
				return nil, fmt.Errorf("line %d: failed to apply the property %#v: %w",
					ml.currentLine, v, err)
			}
		case endOfFile:
			break loop
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

type maintainersLexer struct {
	scanner     *bufio.Scanner
	currentLine int
	inComment   bool
}

type recordTitle string
type recordProperty struct {
	key   string
	value string
}
type endOfFile struct{}

var propertyRe = regexp.MustCompile(`^([[:alpha:]]):\s+(.*).*$`)

func (ml *maintainersLexer) next() interface{} {
	for ml.scanner.Scan() {
		ml.currentLine++
		rawLine := ml.scanner.Text()
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, ".") {
			ml.inComment = true
			continue
		}
		// A comment continues to the next line(s) if they begin with a space character.
		if ml.inComment && (line == "" || !unicode.IsSpace(rune(rawLine[0]))) {
			ml.inComment = false
		}
		if ml.inComment || line == "" {
			continue
		}
		// Now let's consider the possible line types.
		if matches := propertyRe.FindStringSubmatch(line); matches != nil {
			return recordProperty{key: matches[1], value: matches[2]}
		}
		return recordTitle(line)
	}
	return endOfFile{}
}

func applyProperty(record *maintainersRecord, property *recordProperty) error {
	switch property.key {
	case "F":
		record.includePatterns = append(record.includePatterns, property.value)
	case "X":
		record.excludePatterns = append(record.excludePatterns, property.value)
	case "N":
		if _, err := regexp.Compile(property.value); err != nil {
			return fmt.Errorf("invalid regexp: %s", property.value)
		}
		record.regexps = append(record.regexps, property.value)
	case "M":
		value, err := parseEmail(property.value)
		if err != nil {
			return err
		}
		record.maintainers = append(record.maintainers, value)
	case "L":
		value, err := parseEmail(property.value)
		if err != nil {
			return err
		}
		record.lists = append(record.lists, value)
	case "T":
		record.trees = append(record.trees, property.value)
	}
	return nil
}

func parseEmail(value string) (string, error) {
	// Sometimes there happen extra symbols at the end of the line,
	// let's make this parser more error tolerant.
	pos := strings.LastIndexAny(value, ">)")
	if pos >= 0 {
		value = value[:pos+1]
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", err
	}
	return addr.Address, nil
}

func (r maintainersRecord) ToPathRule() subsystem.PathRule {
	inclRe := strings.Builder{}
	for i, wildcard := range r.includePatterns {
		if i > 0 {
			inclRe.WriteByte('|')
		}
		wildcardToRegexp(wildcard, &inclRe)
	}
	for _, rg := range r.regexps {
		if inclRe.Len() > 0 {
			inclRe.WriteByte('|')
		}
		inclRe.WriteString(rg)
	}
	exclRe := strings.Builder{}
	for i, wildcard := range r.excludePatterns {
		if i > 0 {
			exclRe.WriteByte('|')
		}
		wildcardToRegexp(wildcard, &exclRe)
	}
	return subsystem.PathRule{
		IncludeRegexp: inclRe.String(),
		ExcludeRegexp: exclRe.String(),
	}
}

func removeMatchingPatterns(records []*maintainersRecord, rule *regexp.Regexp) {
	filter := func(list []string) []string {
		ret := []string{}
		for _, item := range list {
			if !rule.MatchString(item) {
				ret = append(ret, item)
			}
		}
		return ret
	}
	for _, record := range records {
		record.includePatterns = filter(record.includePatterns)
		record.excludePatterns = filter(record.excludePatterns)
	}
}

var (
	escapedSeparator = regexp.QuoteMeta(fmt.Sprintf("%c", filepath.Separator))
	wildcardReplace  = map[byte]string{
		'*': `[^` + escapedSeparator + `]*`,
		'?': `.`,
		'/': escapedSeparator,
	}
)

func wildcardToRegexp(wildcard string, store *strings.Builder) {
	store.WriteByte('^')

	// We diverge a bit from the standard MAINTAINERS rule semantics.
	// path/* corresponds to the files belonging to the `path` folder,
	// but, since we also infer the parent-child relationship, it's
	// easier to make it cover the whole subtree.
	if len(wildcard) >= 2 && wildcard[len(wildcard)-2:] == "/*" {
		wildcard = wildcard[:len(wildcard)-1]
	}

	tokenStart := 0
	for i, c := range wildcard {
		replace, exists := wildcardReplace[byte(c)]
		if !exists {
			continue
		}
		store.WriteString(regexp.QuoteMeta(wildcard[tokenStart:i]))
		store.WriteString(replace)
		tokenStart = i + 1
	}
	if tokenStart < len(wildcard) {
		store.WriteString(regexp.QuoteMeta(wildcard[tokenStart:]))
	}
	if wildcard == "" || wildcard[len(wildcard)-1] != '/' {
		store.WriteByte('$')
	}
}
