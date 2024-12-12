// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ifaceprobe implements dynamic component of automatic kernel interface extraction.
// Currently it discovers all /{dev,sys,proc} files, and collects coverage for open/read/write/mmap/ioctl
// syscalls on these files. Later this allows to build file path <-> file_operations mapping.
package ifaceprobe

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
)

// Info represents information about dynamically extracted information.
type Info struct {
	Files []FileInfo
	PCs   []PCInfo
}

type FileInfo struct {
	Name  string // Full file name, e.g. /dev/null.
	Cover []int  // Combined coverage for operations on the file.
}

type PCInfo struct {
	Func string
	File string
}

// Run does dynamic analysis and returns dynamic info.
// As it runs it will submit some test program requests to the exec queue.
func Run(ctx context.Context, cfg *mgrconfig.Config, features flatrpc.Feature, exec queue.Executor) (*Info, error) {
	return (&prober{
		ctx:      ctx,
		cfg:      cfg,
		features: features,
		exec:     exec,
		done:     make(chan *fileDesc, 100),
		errc:     make(chan error, 1),
	}).run()
}

type prober struct {
	ctx      context.Context
	cfg      *mgrconfig.Config
	features flatrpc.Feature
	exec     queue.Executor
	wg       sync.WaitGroup
	done     chan *fileDesc
	errc     chan error
}

type fileDesc struct {
	file    string
	results []*queue.Result
}

func (pr *prober) run() (*Info, error) {
	symb := symbolizer.NewSymbolizer(pr.cfg.SysTarget)
	defer symb.Close()

	for _, glob := range globList() {
		pr.submitGlob(glob)
	}

	go func() {
		pr.wg.Wait()
		close(pr.done)
	}()

	info := &Info{}
	pcIndexes := make(map[uint64]int)
	kernelObj := filepath.Join(pr.cfg.KernelObj, pr.cfg.SysTarget.KernelObject)
	sourceBase := filepath.Clean(pr.cfg.KernelSrc) + string(filepath.Separator)
	i := 0
	for desc := range pr.done {
		i++
		if i%500 == 0 {
			log.Logf(0, "done file %v", i)
		}
		fi := FileInfo{
			Name: desc.file,
		}
		fileDedup := make(map[uint64]bool)
		for _, res := range desc.results {
			cover := append(res.Info.Calls[0].Cover, res.Info.Calls[1].Cover...)
			for _, pc := range cover {
				if fileDedup[pc] {
					continue
				}
				fileDedup[pc] = true
				pcIndex, ok := pcIndexes[pc]
				if !ok {
					pcIndex = -1
					frames, err := symb.Symbolize(kernelObj, pc)
					if err != nil {
						return nil, err
					}
					if len(frames) != 0 {
						// Look only at the non-inline frame,
						// callbacks we are looking for can't be inlined.
						frame := frames[len(frames)-1]
						pcIndex = len(info.PCs)
						info.PCs = append(info.PCs, PCInfo{
							Func: frame.Func,
							File: strings.TrimPrefix(filepath.Clean(frame.File), sourceBase),
						})
					}
					pcIndexes[pc] = pcIndex
				}
				if pcIndex >= 0 {
					fi.Cover = append(fi.Cover, pcIndex)
				}
			}
		}
		slices.Sort(fi.Cover)
		info.Files = append(info.Files, fi)
	}
	slices.SortFunc(info.Files, func(a, b FileInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	select {
	case err := <-pr.errc:
		return nil, err
	default:
		return info, nil
	}
}

func (pr *prober) noteError(err error) {
	select {
	case pr.errc <- err:
	default:
	}
}

func (pr *prober) submitGlob(glob string) {
	pr.wg.Add(1)
	req := &queue.Request{
		Type:        flatrpc.RequestTypeGlob,
		GlobPattern: glob,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags: flatrpc.ExecEnvSandboxNone | csource.FeaturesToFlags(pr.features, nil),
		},
		Important: true,
	}
	req.OnDone(pr.onGlobDone)
	pr.exec.Submit(req)
}

func (pr *prober) onGlobDone(req *queue.Request, res *queue.Result) bool {
	defer pr.wg.Done()
	if res.Status != queue.Success {
		pr.noteError(fmt.Errorf("failed to execute glob: %w (%v)\n%s\n%s",
			res.Err, res.Status, req.GlobPattern, res.Output))
	}
	files := res.GlobFiles()
	log.Logf(0, "glob %v expanded to %v files", req.GlobPattern, len(files))
	for _, file := range files {
		if extractFileFilter(file) {
			pr.submitFile(file)
		}
	}
	return true
}

func (pr *prober) submitFile(file string) {
	pr.wg.Add(1)
	var fops = []struct {
		mode string
		call string
	}{
		{mode: "O_RDONLY", call: "read(r0, &AUTO=' ', AUTO)"},
		{mode: "O_WRONLY", call: "write(r0, &AUTO=' ', AUTO)"},
		{mode: "O_RDONLY", call: "ioctl(r0, 0x0, 0x0)"},
		{mode: "O_WRONLY", call: "ioctl(r0, 0x0, 0x0)"},
		{mode: "O_RDONLY", call: "mmap(0x0, 0x1000, 0x1, 0x2, r0, 0)"},
		{mode: "O_WRONLY", call: "mmap(0x0, 0x1000, 0x2, 0x2, r0, 0)"},
	}
	desc := &fileDesc{
		file: file,
	}
	var reqs []*queue.Request
	for _, desc := range fops {
		text := fmt.Sprintf("r0 = openat(0x%x, &AUTO='%s', 0x%x, 0x0)\n%v",
			pr.constVal("AT_FDCWD"), file, pr.constVal(desc.mode), desc.call)
		p, err := pr.cfg.Target.Deserialize([]byte(text), prog.StrictUnsafe)
		if err != nil {
			panic(fmt.Sprintf("failed to deserialize: %v\n%v", err, text))
		}
		req := &queue.Request{
			Prog: p,
			ExecOpts: flatrpc.ExecOpts{
				EnvFlags: flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSignal |
					csource.FeaturesToFlags(pr.features, nil),
				ExecFlags: flatrpc.ExecFlagCollectCover,
			},
			Important: true,
		}
		reqs = append(reqs, req)
		pr.exec.Submit(req)
	}
	go func() {
		defer pr.wg.Done()
		for _, req := range reqs {
			res := req.Wait(pr.ctx)
			if res.Status != queue.Success {
				pr.noteError(fmt.Errorf("failed to execute prog: %w (%v)\n%s\n%s",
					res.Err, res.Status, req.Prog.Serialize(), res.Output))
				continue
			}
			desc.results = append(desc.results, res)
		}
		pr.done <- desc
	}()
}

func (pr *prober) constVal(name string) uint64 {
	val, ok := pr.cfg.Target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not present", name))
	}
	return val
}

// globList returns a list of glob's we are interested in.
func globList() []string {
	var globs []string
	// /selinux is mounted by executor, we probably should mount it at the standard /sys/fs/selinux,
	// but this is where it is now.
	// Also query the test cwd, executor creates some links in there.
	for _, path := range []string{"/dev", "/sys", "/proc", "/selinux", "."} {
		// Our globs currently do not support recursion (#4906),
		// so we append N "/*" parts manully. Some of the paths can be very deep, e.g. try:
		// sudo find /sys -ls 2>/dev/null | sed "s#[^/]##g" | sort | uniq -c
		for i := 1; i < 15; i++ {
			globs = append(globs, path+strings.Repeat("/*", i))
		}
	}
	return globs
}

func extractFileFilter(file string) bool {
	if strings.HasPrefix(file, "/dev/") ||
		strings.HasPrefix(file, "/selinux/") ||
		strings.HasPrefix(file, "./") {
		return true
	}
	if proc := "/proc/"; strings.HasPrefix(file, proc) {
		// These won't be present in the test process.
		if strings.HasPrefix(file, "/proc/self/fdinfo/") ||
			strings.HasPrefix(file, "/proc/thread-self/fdinfo/") {
			return false
		}
		// It contains actual pid number that will be different in the test.
		if strings.HasPrefix(file, "/proc/self/task/") {
			return false
		}
		// Ignore all actual processes.
		c := file[len(proc)]
		return c < '0' || c > '9'
	}
	if strings.HasPrefix(file, "/sys/") {
		// There are too many tracing events, so leave just one of them.
		if strings.HasPrefix(file, "/sys/kernel/tracing/events/") &&
			!strings.HasPrefix(file, "/sys/kernel/tracing/events/vmalloc/") ||
			strings.HasPrefix(file, "/sys/kernel/debug/tracing/events/") &&
				!strings.HasPrefix(file, "/sys/kernel/debug/tracing/events/vmalloc/") {
			return false
		}
		// There are too many slabs, so leave just one of them.
		if strings.HasPrefix(file, "/sys/kernel/slab/") &&
			!strings.HasPrefix(file, "/sys/kernel/slab/kmalloc-64") {
			return false
		}
		// There are too many of these, leave just one of them.
		if strings.HasPrefix(file, "/sys/fs/selinux/class/") &&
			!strings.HasPrefix(file, "/sys/fs/selinux/class/file/") {
			return false
		}
		return true
	}
	panic(fmt.Sprintf("unhandled file %q", file))
}
