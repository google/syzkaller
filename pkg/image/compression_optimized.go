// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !windows && !386 && !arm

package image

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"sync"
	"syscall"
	"unsafe"
)

// Temporary scratch data used by the decompression procedure.
type decompressScratch struct {
	r   bytes.Reader
	zr  io.Reader
	buf []byte
}

var decompressPool = sync.Pool{New: func() interface{} {
	return &decompressScratch{
		buf: make([]byte, 8<<10),
	}
}}

func mustDecompress(compressed []byte) (data []byte, dtor func()) {
	// Optimized decompression procedure that is ~2x faster than a naive version
	// and consumes significantly less memory and generates less garbage.
	// Images tend to contain lots of 0s, especially the larger images.
	// The main idea is that we mmap a buffer and then don't write 0s into it
	// (since it already contains all 0s). As the result if a page is all 0s
	// then we don't page it in and don't consume memory for it.
	// Executor uses the same optimization during decompression.
	scratch := decompressPool.Get().(*decompressScratch)
	defer decompressPool.Put(scratch)
	scratch.r.Reset(compressed)
	if scratch.zr == nil {
		zr, err := zlib.NewReader(&scratch.r)
		if err != nil {
			panic(err)
		}
		scratch.zr = zr
	} else {
		if err := scratch.zr.(zlib.Resetter).Reset(&scratch.r, nil); err != nil {
			panic(err)
		}
	}
	// We don't know the size of the uncompressed image.
	// We could uncompress it into ioutil.Discard first, then allocate memory and uncompress second time
	// (and it's still faster than the naive uncompress into bytes.Buffer!).
	// But we know maximum size of images, so just mmap the max size.
	// It's fast and unused part does not consume memory.
	// Note: executor/common_zlib.h also knows this const.
	const maxImageSize = 132 << 20
	var err error
	data, err = syscall.Mmap(-1, 0, maxImageSize, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		panic(err)
	}
	dtor = func() {
		if err := syscall.Munmap(data[:maxImageSize]); err != nil {
			panic(err)
		}
	}
	offset := 0
	for {
		n, err := scratch.zr.Read(scratch.buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}
		if offset+n > len(data) {
			panic(fmt.Sprintf("bad image size: offset=%v n=%v data=%v", offset, n, len(data)))
		}
		// Copy word-at-a-time and avoid bounds checks in the loop,
		// this is considerably faster than a naive byte loop.
		// We already checked bounds above.
		type word uint64
		const wordSize = unsafe.Sizeof(word(0))
		// Don't copy the last word b/c otherwise we calculate pointer outside of scratch.buf object
		// on the last iteration. We don't use it, but unsafe rules prohibit even calculating
		// such pointers. Alternatively we could add 8 unused bytes to scratch.buf, but it will
		// play badly with memory allocator size classes (it will consume whole additional page,
		// or whatever is the alignment for such large objects). We could also break from the middle
		// of the loop before updating src/dst pointers, but it hurts codegen a lot (compilers like
		// canonical loop forms).
		words := uintptr(n-1) / wordSize
		src := (*word)(unsafe.Pointer(&scratch.buf[0]))
		dst := (*word)(unsafe.Pointer(&data[offset]))
		for i := uintptr(0); i < words; i++ {
			if *src != 0 {
				*dst = *src
			}
			src = (*word)(unsafe.Pointer(uintptr(unsafe.Pointer(src)) + wordSize))
			dst = (*word)(unsafe.Pointer(uintptr(unsafe.Pointer(dst)) + wordSize))
		}
		// Copy any remaining trailing bytes.
		for i := words * wordSize; i < uintptr(n); i++ {
			v := scratch.buf[i]
			if v != 0 {
				data[uintptr(offset)+i] = v
			}
		}
		offset += n
	}
	data = data[:offset]
	return
}
