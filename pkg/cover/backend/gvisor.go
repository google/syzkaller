// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func makeGvisor(target *targets.Target, objDir, srcDir, buildDir string, modules []host.KernelModule) (*Impl, error) {
	if len(modules) != 0 {
		return nil, fmt.Errorf("gvisor coverage does not support modules")
	}
	bin := filepath.Join(objDir, target.KernelObject)
	// pkg/build stores runsc as 'vmlinux' (we pretent to be linux), but a local build will have it as 'runsc'.
	if !osutil.IsExist(bin) {
		bin = filepath.Join(filepath.Dir(bin), "runsc")
	}
	frames, err := gvisorSymbolize(bin, srcDir)
	if err != nil {
		return nil, err
	}
	unitMap := make(map[string]*CompileUnit)
	for _, frame := range frames {
		unit := unitMap[frame.Name]
		if unit == nil {
			unit = &CompileUnit{
				ObjectUnit: ObjectUnit{
					Name: frame.Name,
				},
				Path: frame.Path,
			}
			unitMap[frame.Name] = unit
		}
		unit.PCs = append(unit.PCs, frame.PC)
	}
	var units []*CompileUnit
	for _, unit := range unitMap {
		units = append(units, unit)
	}
	impl := &Impl{
		Units:  units,
		Frames: frames,
		RestorePC: func(pc uint32) uint64 {
			return uint64(pc)
		},
	}
	return impl, nil
}

func gvisorSymbolize(bin, srcDir string) ([]Frame, error) {
	cmd := osutil.Command(bin, "symbolize", "-all")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Wait()
	var frames []Frame
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		frame, err := gvisorParseLine(s)
		if err != nil {
			return nil, err
		}
		frame.Path = filepath.Join(srcDir, frame.Name)
		if !osutil.IsExist(frame.Path) {
			// Try to locate auto-generated files.
			// Note: some files are only present under some hashed path,
			// e.g. bazel-out/k8-fastbuild-ST-4c64f0b3d5c7/bin/pkg/usermem/addr_range.go,
			// it's unclear how we can locate them. In a local run that may be under objDir,
			// but this is not the case for syz-ci.
			path := filepath.Join(srcDir, "bazel-out", "k8-fastbuild", "bin", frame.Name)
			if osutil.IsExist(path) {
				frame.Path = path
			}
		}
		frames = append(frames, frame)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return frames, nil
}

func gvisorParseLine(s *bufio.Scanner) (Frame, error) {
	pc, err := strconv.ParseUint(s.Text(), 0, 64)
	if err != nil {
		return Frame{}, fmt.Errorf("read pc %q, but no line info", pc)
	}
	if !s.Scan() {
		return Frame{}, fmt.Errorf("read pc %q, but no line info", pc)
	}
	match := gvisorLineRe.FindStringSubmatch(s.Text())
	if match == nil {
		return Frame{}, fmt.Errorf("failed to parse line: %q", s.Text())
	}
	var ints [4]int
	for i := range ints {
		x, err := strconv.ParseUint(match[i+2], 0, 32)
		if err != nil {
			return Frame{}, fmt.Errorf("failed to parse number %q: %v", match[i+2], err)
		}
		ints[i] = int(x)
	}
	frame := Frame{
		PC:   pc,
		Name: match[1],
		Range: Range{
			StartLine: ints[0],
			StartCol:  ints[1],
			EndLine:   ints[2],
			EndCol:    ints[3],
		},
	}
	return frame, nil
}

var gvisorLineRe = regexp.MustCompile(`/gvisor/([^:]+):([0-9]+).([0-9]+),([0-9]+).([0-9]+)$`)
