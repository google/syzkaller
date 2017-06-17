// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
	"strings"
)

var (
	filename  = regexp.MustCompile(`[a-zA-Z0-9_\-\./]*[a-zA-Z0-9_\-]+\.(c|h):[0-9]+`)
	blacklist = []*regexp.Regexp{
		regexp.MustCompile(`.*\.h`),
		regexp.MustCompile(`^lib/.*`),
		regexp.MustCompile(`^virt/lib/.*`),
		regexp.MustCompile(`^mm/kasan/.*`),
		regexp.MustCompile(`^mm/kmsan/.*`),
		regexp.MustCompile(`^mm/percpu.*`),
		regexp.MustCompile(`^mm/vmalloc.c`),
		regexp.MustCompile(`^mm/page_alloc.c`),
		regexp.MustCompile(`^kernel/rcu/.*`),
		regexp.MustCompile(`^arch/.*/kernel/traps.c`),
		regexp.MustCompile(`^kernel/locking/*`),
		regexp.MustCompile(`^kernel/panic.c`),
		regexp.MustCompile(`^kernel/softirq.c`),
		regexp.MustCompile(`^net/core/dev.c`),
		regexp.MustCompile(`^net/core/sock.c`),
		regexp.MustCompile(`^net/core/skbuff.c`),
	}
)

func extractFiles(log string) []string {
	matches := filename.FindAllString(log, -1)
	var files []string
	for _, match := range matches {
		files = append(files, strings.Split(match, ":")[0])
	}
	return files
}

func ExtractGuiltyFile(log string) string {
	files := extractFiles(log)
nextFile:
	for _, file := range files {
		for _, re := range blacklist {
			if re.MatchString(file) {
				continue nextFile
			}
		}
		return file
	}
	return ""
}
