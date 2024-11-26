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
	Name  string   // Full file name, e.g. /dev/null.
	Cover []uint64 // Combined coverage for operations on the file.
}

type PCInfo struct {
	PC   uint64
	Func string
	File string
}

// Globs returns a list of glob's that should be requested from the target machine.
// Result of querying these globs should be later passed to Run in info.
func Globs() []string {
	var globs []string
	for _, path := range []string{"/dev", "/sys", "/proc"} {
		// Our globs currently do not support recursion (#4906),
		// so we append N "/*" parts manully. Some of the paths can be very deep, e.g. try:
		// sudo find /sys -ls 2>/dev/null | sed "s#[^/]##g" | sort | uniq -c
		for i := 1; i < 15; i++ {
			globs = append(globs, path+strings.Repeat("/*", i))
		}
	}
	return globs
}

// Run finishes dynamic analysis and returns dynamic info.
// As it runs it will submit some test program requests to the exec queue.
// Info is used to extract results of glob querying, see Globs function.
func Run(ctx context.Context, cfg *mgrconfig.Config, exec queue.Executor, info *flatrpc.InfoRequest) (*Info, error) {
	return (&prober{
		ctx:  ctx,
		cfg:  cfg,
		exec: exec,
		info: info,
	}).run()
}

type prober struct {
	ctx  context.Context
	cfg  *mgrconfig.Config
	exec queue.Executor
	info *flatrpc.InfoRequest
}

func (pr *prober) run() (*Info, error) {
	symb := symbolizer.NewSymbolizer(pr.cfg.SysTarget)
	defer symb.Close()

	files := extractFiles(pr.info)
	var reqs [][]*queue.Request
	for _, file := range extractFiles(pr.info) {
		reqs1, err := pr.submitFile(file)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, reqs1)
	}

	info := &Info{}
	dedup := make(map[uint64]bool)
	kernelObj := filepath.Join(pr.cfg.KernelObj, pr.cfg.SysTarget.KernelObject)
	sourceBase := filepath.Clean(pr.cfg.KernelSrc) + string(filepath.Separator)
	for i, file := range files {
		if i%500 == 0 {
			log.Logf(0, "processing file %v/%v", i, len(files))
		}
		fi := FileInfo{
			Name: file,
		}
		fileDedup := make(map[uint64]bool)
		for _, req := range reqs[i] {
			res := req.Wait(pr.ctx)
			if res.Status != queue.Success {
				return nil, fmt.Errorf("failed to execute prog: %w (%v)", res.Err, res.Status)
			}
			cover := append(res.Info.Calls[0].Cover, res.Info.Calls[1].Cover...)
			for _, pc := range cover {
				if fileDedup[pc] {
					continue
				}
				fileDedup[pc] = true
				fi.Cover = append(fi.Cover, pc)
				if dedup[pc] {
					continue
				}
				dedup[pc] = true
				frames, err := symb.Symbolize(kernelObj, pc)
				if err != nil {
					return nil, err
				}
				if len(frames) == 0 {
					continue
				}
				// Look only at the non-inline frame, callbacks we are looking for can't be inlined.
				frame := frames[len(frames)-1]
				info.PCs = append(info.PCs, PCInfo{
					PC:   pc,
					Func: frame.Func,
					File: strings.TrimPrefix(filepath.Clean(frame.File), sourceBase),
				})
			}
		}
		slices.Sort(fi.Cover)
		info.Files = append(info.Files, fi)
	}
	slices.SortFunc(info.PCs, func(a, b PCInfo) int {
		return int(a.PC - b.PC)
	})
	return info, nil
}

func (pr *prober) submitFile(file string) ([]*queue.Request, error) {
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
	var reqs []*queue.Request
	for _, desc := range fops {
		text := fmt.Sprintf("r0 = openat(0x%x, &AUTO='%s', 0x%x, 0x0)\n%v",
			pr.constVal("AT_FDCWD"), file, pr.constVal(desc.mode), desc.call)
		p, err := pr.cfg.Target.Deserialize([]byte(text), prog.StrictUnsafe)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize: %w\n%v", err, text)
		}
		req := &queue.Request{
			Prog: p,
			ExecOpts: flatrpc.ExecOpts{
				EnvFlags:  flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSignal,
				ExecFlags: flatrpc.ExecFlagCollectCover,
			},
			Important: true,
		}
		reqs = append(reqs, req)
		pr.exec.Submit(req)
	}
	return reqs, nil
}

func (pr *prober) constVal(name string) uint64 {
	val, ok := pr.cfg.Target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not present", name))
	}
	return val
}

func extractFiles(info *flatrpc.InfoRequestRawT) []string {
	var files []string
	dedup := make(map[string]bool)
	for _, glob := range info.Globs {
		for _, file := range glob.Files {
			if dedup[file] || !extractFileFilter(file) {
				continue
			}
			dedup[file] = true
			files = append(files, file)
		}
	}
	return files
}

func extractFileFilter(file string) bool {
	if strings.HasPrefix(file, "/dev/") {
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
	return false
}
