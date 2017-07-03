// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
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

func extractFiles(report []byte) []string {
	matches := filename.FindAll(report, -1)
	var files []string
	for _, match := range matches {
		files = append(files, string(bytes.Split(match, []byte{':'})[0]))
	}
	return files
}

func ExtractGuiltyFile(report []byte) string {
	files := extractFiles(report)
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

func getMaintainersImpl(linux, file string, blame bool) ([]string, error) {
	// ./scripts/get_maintainer.pl is a Linux kernel script.
	args := []string{"--no-n", "--no-rolestats"}
	if blame {
		args = append(args, "--git-blame")
	}
	args = append(args, file)
	output, err := osutil.RunCmd(time.Minute, linux, "./scripts/get_maintainer.pl", args...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	var mtrs []string
	for _, line := range lines {
		addr, err := mail.ParseAddress(line)
		if err != nil {
			continue
		}
		mtrs = append(mtrs, addr.Address)
	}
	return mtrs, nil
}

func GetMaintainers(linux, file string) ([]string, error) {
	mtrs, err := getMaintainersImpl(linux, file, false)
	if err != nil {
		return nil, err
	}
	if len(mtrs) <= 1 {
		mtrs, err = getMaintainersImpl(linux, file, true)
		if err != nil {
			return nil, err
		}
	}
	return mtrs, nil
}
