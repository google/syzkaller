// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bufio"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// maintainersRecord represents a single raw record in the MAINTAINERS file.
type maintainersRecord struct {
	name            string
	includePatterns []string
	excludePatterns []string
	regexps         []string
	lists           []string
	maintainers     []string
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
