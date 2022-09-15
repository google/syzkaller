// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"io"

	"github.com/google/syzkaller/prog"
)

type zeroReader struct {
	left int
}

func (zr *zeroReader) Read(p []byte) (n int, err error) {
	if zr.left == 0 {
		return 0, io.EOF
	}
	toRead := zr.left
	if toRead > len(p) {
		toRead = len(p)
	}
	for i := 0; i < toRead; i++ {
		p[i] = 0
	}
	return toRead, nil
}

func newZeroReader(size int) io.Reader {
	return &zeroReader{left: size}
}

const imageMaxSize = 129 << 20

func fixUpImageSegments(parsed *mountImageArgs) {
	parsed.filterSegments(func(i int, segment *mountImageSegment) bool {
		if segment.parseError != nil {
			return false
		}
		return segment.offset.Val < imageMaxSize && segment.size.Val < imageMaxSize
	})
	newSize := parsed.size.Val
	for _, segment := range parsed.segments {
		actualSize := uint64(len(segment.data.Data()))
		if segment.size.Val > actualSize {
			segment.size.Val = actualSize
		}
		if segment.offset.Val+segment.size.Val > imageMaxSize {
			segment.offset.Val = imageMaxSize - segment.size.Val
		}
		if segment.offset.Val+segment.size.Val > newSize {
			newSize = segment.offset.Val + segment.size.Val
		}
	}
	if newSize > imageMaxSize {
		newSize = imageMaxSize
	}
	parsed.size.Val = newSize
}

func (arch *arch) fixUpSyzMountImage(c *prog.Call) {
	// Previously we did such a sanitization right in the common_linux.h, but this was problematic
	// for two reasons:
	// 1) It further complicates the already complicated executor code.
	// 2) We'd need to duplicate the logic in Go for raw image extraction.
	// So now we do all the initialization in Go and let the C code only interpret the commands.
	ret, err := parseSyzMountImage(c)
	if err != nil {
		deactivateSyzMountImage(c)
		return
	}
	const maxImageSegments = 4096
	ret.filterSegments(func(i int, _ *mountImageSegment) bool {
		return i < maxImageSegments
	})
	fixUpImageSegments(ret)
}

type mountImageArgs struct {
	size          *prog.ConstArg
	segmentsCount *prog.ConstArg
	segmentsGroup *prog.GroupArg
	segments      []*mountImageSegment
}

func (m *mountImageArgs) filterSegments(filter func(int, *mountImageSegment) bool) {
	newArgs := []prog.Arg{}
	newSegments := []*mountImageSegment{}
	for i, segment := range m.segments {
		if filter(i, segment) {
			newSegments = append(newSegments, segment)
			newArgs = append(newArgs, m.segmentsGroup.Inner[i])
		}
	}
	m.segments = newSegments
	m.segmentsGroup.Inner = newArgs
	m.segmentsCount.Val = uint64(len(newArgs))
}

type mountImageSegment struct {
	data       *prog.DataArg
	offset     *prog.ConstArg
	size       *prog.ConstArg
	parseError error
}

func parseImageSegment(segmentArg prog.Arg) *mountImageSegment {
	ret := &mountImageSegment{}
	segmentFields, ok := segmentArg.(*prog.GroupArg)
	if segmentFields == nil || !ok {
		return &mountImageSegment{parseError: fmt.Errorf("it is not a group")}
	}
	if len(segmentFields.Inner) != 3 {
		return &mountImageSegment{parseError: fmt.Errorf("invalid number of nested fields")}
	}
	dataPtr, ok := segmentFields.Inner[0].(*prog.PointerArg)
	if dataPtr == nil || dataPtr.Res == nil || !ok {
		return &mountImageSegment{parseError: fmt.Errorf("invalid data field ptr")}
	}
	ret.data, ok = dataPtr.Res.(*prog.DataArg)
	if ret.data == nil || !ok {
		return &mountImageSegment{parseError: fmt.Errorf("invalid data arg")}
	}
	ret.size, ok = segmentFields.Inner[1].(*prog.ConstArg)
	if ret.size == nil || !ok {
		return &mountImageSegment{parseError: fmt.Errorf("invalid size arg")}
	}
	ret.offset, ok = segmentFields.Inner[2].(*prog.ConstArg)
	if ret.offset == nil || !ok {
		return &mountImageSegment{parseError: fmt.Errorf("invalid offset arg")}
	}
	return ret
}

func deactivateSyzMountImage(c *prog.Call) {
	groupArg := c.Args[4]
	newArg := groupArg.Type().DefaultArg(groupArg.Dir())
	prog.RemoveArg(groupArg)
	c.Args[4] = newArg
	// Also set the segments count field to 0.
	c.Args[3].(*prog.ConstArg).Val = 0
}

func parseSyzMountImage(c *prog.Call) (*mountImageArgs, error) {
	if len(c.Args) < 5 {
		panic("invalid number of arguments in syz_mount_image")
	}
	segmentsCountArg, ok := c.Args[3].(*prog.ConstArg)
	if !ok {
		panic("syz_mount_image's segment count was expected to be const")
	}
	sizeArg, ok := c.Args[2].(*prog.ConstArg)
	if !ok {
		panic("syz_mount_image's size arg is not const")
	}
	segmentsPtrArg, ok := c.Args[4].(*prog.PointerArg)
	if !ok {
		return nil, fmt.Errorf("invalid segments arg")
	}
	segmentsGroup, ok := segmentsPtrArg.Res.(*prog.GroupArg)
	if segmentsGroup == nil || !ok {
		return nil, fmt.Errorf("segments are not a group")
	}
	ret := &mountImageArgs{
		segmentsCount: segmentsCountArg,
		segmentsGroup: segmentsGroup,
		size:          sizeArg,
	}
	for _, segmentArg := range segmentsGroup.Inner {
		parsed := parseImageSegment(segmentArg)
		ret.segments = append(ret.segments, parsed)
	}
	return ret, nil
}
