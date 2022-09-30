// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/google/syzkaller/prog"
)

func (arch *arch) extractSyzMountImage(c *prog.Call) (io.Reader, error) {
	// In order to reduce the size of syzlang programs, disk imags are de facto compressed.
	// Here we do the uncompression.
	if c.Meta.CallName != "syz_mount_image" {
		return nil, nil
	}
	ret, err := parseSyzMountImage(c)
	if err != nil {
		// Parsing failed --> do not try to recover, just ignore.
		return nil, err
	} else if len(ret.segments) == 0 {
		return nil, fmt.Errorf("an empty image")
	}
	readers := []io.Reader{}
	nextPos := 0
	// Add fake zero readers between segments, so that we can combine them to read the whole image.
	for _, segment := range ret.segments {
		offset := int(segment.offset.Val)
		if offset > nextPos {
			readers = append(readers, &zeroReader{left: offset - nextPos})
		}
		size := int(segment.size.Val)
		readers = append(readers, bytes.NewReader(segment.data.Data()[0:size]))
		nextPos = offset + size
	}
	if int(ret.size.Val) > nextPos {
		readers = append(readers, &zeroReader{left: int(ret.size.Val) - nextPos})
	}
	return io.MultiReader(readers...), nil
}

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
	zr.left -= toRead
	return toRead, nil
}

const imageMaxSize = 129 << 20

func fixUpImageSegments(parsed *mountImageArgs, fixStructure bool) error {
	const maxImageSegments = 16784
	err := parsed.filterSegments(func(i int, segment *mountImageSegment) bool {
		if i >= maxImageSegments {
			// We don't want more than maxImageSegments segments.
			return false
		}
		if segment.parseError != nil {
			// Delete mangled segment structures.
			return false
		}
		return segment.offset.Val < imageMaxSize && segment.size.Val < imageMaxSize
	}, !fixStructure)
	if err != nil {
		return err
	}
	// Overwriting of the image multiple times is not efficient and complicates image extraction in Go.
	// So let's make segments non-overlapping.
	if fixStructure {
		sort.Stable(parsed)
	} else if !sort.IsSorted(parsed) {
		return fmt.Errorf("segments are not sorted")
	}

	newSize := parsed.size.Val
	if newSize > imageMaxSize {
		newSize = imageMaxSize
	}

	for idx, segment := range parsed.segments {
		actualSize := uint64(len(segment.data.Data()))
		if segment.size.Val != actualSize {
			segment.size.Val = actualSize
		}
		if idx > 0 {
			// Adjust the end of the previous segment.
			prevSegment := parsed.segments[idx-1]
			if prevSegment.offset.Val+prevSegment.size.Val > segment.offset.Val {
				if fixStructure {
					prevSegment.resize(segment.offset.Val - prevSegment.offset.Val)
				} else {
					return fmt.Errorf("segment %d has invalid size", idx-1)
				}
			}
		}
		if segment.offset.Val+segment.size.Val > imageMaxSize {
			if fixStructure {
				segment.resize(imageMaxSize - segment.offset.Val)
			} else {
				return fmt.Errorf("segment %d has invalid size", idx)
			}
		}
		if segment.offset.Val+segment.size.Val > newSize {
			newSize = segment.offset.Val + segment.size.Val
		}
	}
	if newSize > imageMaxSize {
		// Assert that the logic above is not broken.
		panic("newSize > imageMaxSize")
	}
	parsed.size.Val = newSize

	// Drop 0-size segments.
	return parsed.filterSegments(func(i int, segment *mountImageSegment) bool {
		return segment.size.Val > 0
	}, !fixStructure)
}

func (arch *arch) fixUpSyzMountImage(c *prog.Call, fixStructure bool) error {
	// Previously we did such a sanitization right in the common_linux.h, but this was problematic
	// for two reasons:
	// 1) It further complicates the already complicated executor code.
	// 2) We'd need to duplicate the logic in Go for raw image extraction.
	// So now we do all the initialization in Go and let the C code only interpret the commands.
	ret, err := parseSyzMountImage(c)
	if err != nil {
		if fixStructure {
			deactivateSyzMountImage(c)
			return nil
		}
		return err
	}
	return fixUpImageSegments(ret, fixStructure)
}

type mountImageArgs struct {
	size          *prog.ConstArg
	segmentsCount *prog.ConstArg
	segmentsGroup *prog.GroupArg
	segments      []*mountImageSegment
}

func (m *mountImageArgs) filterSegments(filter func(int, *mountImageSegment) bool, failOnRemove bool) error {
	newArgs := []prog.Arg{}
	newSegments := []*mountImageSegment{}
	for i, segment := range m.segments {
		if filter(i, segment) {
			newSegments = append(newSegments, segment)
			newArgs = append(newArgs, m.segmentsGroup.Inner[i])
		} else if failOnRemove {
			return fmt.Errorf("segment #%d got filtered out", i)
		}
	}
	m.segments = newSegments
	m.segmentsGroup.Inner = newArgs
	m.segmentsCount.Val = uint64(len(newArgs))
	return nil
}

// Methods for segment sorting.
func (m *mountImageArgs) Len() int { return len(m.segments) }
func (m *mountImageArgs) Swap(i, j int) {
	inner := m.segmentsGroup.Inner
	inner[i], inner[j] = inner[j], inner[i]
	m.segments[i], m.segments[j] = m.segments[j], m.segments[i]
}
func (m *mountImageArgs) Less(i, j int) bool {
	if m.segments[i].offset.Val != m.segments[j].offset.Val {
		return m.segments[i].offset.Val < m.segments[j].offset.Val
	}
	return m.segments[i].size.Val < m.segments[j].size.Val
}

type mountImageSegment struct {
	data       *prog.DataArg
	offset     *prog.ConstArg
	size       *prog.ConstArg
	parseError error
}

func (s *mountImageSegment) resize(newSize uint64) {
	s.size.Val = newSize
	s.data.SetData(s.data.Data()[0:newSize])
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
