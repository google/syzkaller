package trace2syz

import (
	"github.com/google/syzkaller/pkg/log"
	"path/filepath"
	"strings"
)

var commonRootPaths = []string{"/home", "/tmp", "/dev/shm", "/root"}
var systemPaths = []string{"/dev", "/proc", "/sys"}

//If the file is under /tmp/, /etc/, we should
type FSEntry struct {
	TraceName string
	IsDir     bool
	Children  map[string]*FSEntry
	Parent    *FSEntry
}

func (e *FSEntry) Child(name string) *FSEntry {
	if _, ok := e.Children[name]; ok {
		return e.Children[name]
	}
	log.Fatalf("Looking for file/dir %s that doesn't exit", name)
	return nil
}

type FileTracker struct {
	CWD         *FSEntry
	SandboxHome *FSEntry
}

func (f *FileTracker) chdir(path string) {
	cleanPath := filepath.Clean(path)
	split := filepath.SplitList(cleanPath)
	for _, part := range split {
		switch part {
		case ".":
		case "..":
			if f.CWD == f.SandboxHome {
				continue
			}
			if f.CWD.Parent != nil {
				f.CWD = f.CWD.Parent
			}
		default:

		}
	}
}

func (f *FileTracker) sanitize(path string) string {
	var sanitized string
	if isSystemFile(path) {
		return path
	}
	for _, p := range commonRootPaths {
		if strings.HasPrefix(path, p) {
			sanitized = strings.TrimPrefix(path, p)
			break
		}
	}

	if sanitized == "" {
		return "."
	}
	return sanitized
}

func isSystemFile(path string) bool {
	/*
		Determine if the file is a system wide file
		This is mainly to determine if we need to generate a new path
		that is contained inside of a sandbox
	*/
	for _, p := range systemPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func isTempFile(path string) bool {
	if isAbsPath(path) {
		split := filepath.SplitList(path)
		if len(split) == 0 {
			return false
		}
		switch split[0] {
		case "dev":
			if len(split) >= 1 {
				if split[1] == "shm" {
					return true
				}
			}
		case "tmp":
			return true
		default:
			return false
		}
	}
	return false
}

func isAbsPath(filename string) bool {
	if filename[0] == '/' {
		return true
	}
	return false
}
