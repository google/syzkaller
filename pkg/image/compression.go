// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package image

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
)

func Compress(rawData []byte) []byte {
	var buffer bytes.Buffer
	zlibWriter := zlib.NewWriter(&buffer)

	_, err := zlibWriter.Write(rawData)
	if err != nil {
		panic(fmt.Sprintf("could not compress with zlib: %v", err))
	}

	err = zlibWriter.Close()
	if err != nil {
		panic(fmt.Sprintf("could not finalize compression with zlib: %v", err))
	}

	return buffer.Bytes()
}

func MustDecompress(compressed []byte) (data []byte, dtor func()) {
	if len(compressed) == 0 {
		return nil, func() {}
	}
	return mustDecompress(compressed)
}

func DecompressCheck(compressed []byte) error {
	return decompressWriter(io.Discard, compressed)
}

func decompressWriter(w io.Writer, compressed []byte) error {
	if len(compressed) == 0 {
		return nil
	}
	zlibReader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("could not initialise zlib: %w", err)
	}

	if _, err := io.Copy(w, zlibReader); err != nil {
		return fmt.Errorf("could not read data with zlib: %w", err)
	}

	return zlibReader.Close()
}

func DecodeB64(b64Data []byte) ([]byte, error) {
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(b64Data))
	rawData, err := io.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("could not decode Base64: %w", err)
	}
	return rawData, nil
}

func EncodeB64(rawData []byte) []byte {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	_, err := encoder.Write(rawData)
	if err != nil {
		panic(fmt.Sprintf("could not encode Base64: %v", err))
	}
	err = encoder.Close()
	if err != nil {
		panic(fmt.Sprintf("could not finalize encoding to Base64: %v", err))
	}
	return buf.Bytes()
}
