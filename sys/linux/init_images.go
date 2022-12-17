// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/prog"
)

func (arch *arch) extractSyzMountImage(c *prog.Call) (io.Reader, error) {
	// In order to reduce the size of syzlang programs, disk images are compressed.
	// Here we extract the compressed image.
	if c.Meta.CallName != "syz_mount_image" {
		return nil, nil
	}
	data, _, err := parseSyzMountImage(c)
	if err != nil {
		// Parsing failed --> do not try to recover, just ignore.
		return nil, err
	} else if len(data) == 0 {
		return nil, fmt.Errorf("an empty image")
	}
	buf := new(bytes.Buffer)
	if err := image.DecompressWriter(buf, data); err != nil {
		return nil, err
	}
	return buf, nil
}

func (arch *arch) fixUpSyzMountImage(c *prog.Call, fixStructure bool) error {
	// Previously we did such a sanitization right in the common_linux.h, but this was problematic
	// for two reasons:
	// 1) It further complicates the already complicated executor code.
	// 2) We'd need to duplicate the logic in Go for raw image extraction.
	// So now we do all the initialization in Go and let the C code only interpret the commands.
	data, sizeArg, err := parseSyzMountImage(c)
	sizeArg.Val = uint64(len(data))
	if err != nil {
		if fixStructure {
			deactivateSyzMountImage(c)
			return nil
		}
		return err
	}
	return nil
}

func deactivateSyzMountImage(c *prog.Call) {
	dataPointer := c.Args[6]
	newArg := dataPointer.Type().DefaultArg(dataPointer.Dir())
	prog.RemoveArg(dataPointer)
	c.Args[6] = newArg
	// Also set the size field to 0.
	c.Args[5].(*prog.ConstArg).Val = 0
}

// Returns the compressed disk image and the corresponding length argument.
func parseSyzMountImage(c *prog.Call) ([]byte, *prog.ConstArg, error) {
	if len(c.Args) < 7 {
		panic("invalid number of arguments in syz_mount_image")
	}

	// Check `size` argument.
	sizeArg, ok := c.Args[5].(*prog.ConstArg)
	if !ok {
		panic("syz_mount_image's size arg is not const")
	}

	dataPointer, ok := c.Args[6].(*prog.PointerArg)
	if !ok {
		panic("syz_mount_image's data pointer is invalid")
	}

	dataArg, ok := dataPointer.Res.(*prog.DataArg)
	if !ok {
		return nil, sizeArg, fmt.Errorf("could not find raw image data")
	}
	if dataArg == nil {
		return nil, sizeArg, fmt.Errorf("image argument contains no data")
	}

	return dataArg.Data(), sizeArg, nil
}
