// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/google/syzkaller/pkg/gcs"
	gcsmocks "github.com/google/syzkaller/pkg/gcs/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGCSGZIPMultiReader_Read(t *testing.T) {
	tests := []struct {
		name       string
		inputFiles []string
		inputBytes [][]byte

		wantBytes []byte
		wantErr   error
	}{
		{
			name:       "single file, single read",
			inputFiles: []string{"file1"},
			inputBytes: [][]byte{gzBytes("1")},
			wantBytes:  []byte("1"),
			wantErr:    nil,
		},
		{
			name:       "single file, multiple reads",
			inputFiles: []string{"file1"},
			inputBytes: [][]byte{gzBytes("123")},
			wantBytes:  []byte("123"),
			wantErr:    nil,
		},
		{
			name:       "multiple files, multiple reads",
			inputFiles: []string{"file1", "file2", "file3"},
			inputBytes: [][]byte{gzBytes("123"), gzBytes("456"), gzBytes("789")},
			wantBytes:  []byte("123456789"),
			wantErr:    nil,
		},
		{
			name:       "multiple files, badbytes",
			inputFiles: []string{"file1", "file2", "file3"},
			inputBytes: [][]byte{gzBytes("123"), gzBytes("456"), []byte("789")},
			wantBytes:  []byte("123456"),
			wantErr:    fmt.Errorf("err calling gzip.NewReader: %w", errors.New("unexpected EOF")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mr := &gcsGZIPMultiReader{
				gcsClient: makeGCSClientMock(t, test.inputFiles, test.inputBytes),
				gcsFiles:  test.inputFiles,
			}
			gotBytes, gotErr := io.ReadAll(mr)
			assert.NoError(t, mr.Close())
			assert.Equal(t, test.wantErr, gotErr)
			assert.Equal(t, test.wantBytes, gotBytes)
		})
	}
}

func makeGCSClientMock(t *testing.T, files []string, bytes [][]byte) gcs.Client {
	gcsClientMock := gcsmocks.NewClient(t)
	for i, file := range files {
		rcMock := &readCloserMock{}
		for _, b := range bytes[i] {
			rcMock.On("Read", mock.Anything).
				Run(func(args mock.Arguments) {
					arg := args.Get(0).([]byte)
					arg[0] = b
				}).
				Return(1, nil).Once()
		}
		rcMock.On("Read", mock.Anything).
			Return(0, io.EOF).
			On("Close").
			Return(nil).Once()

		gcsClientMock.EXPECT().
			FileReader(file).
			Return(rcMock, nil)
	}
	return gcsClientMock
}

type readCloserMock struct {
	mock.Mock
}

func (m *readCloserMock) Read(p []byte) (n int, err error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *readCloserMock) Close() (err error) {
	args := m.Called()
	return args.Error(0)
}

func gzBytes(str string) []byte {
	buf := &bytes.Buffer{}
	gzw := gzip.NewWriter(buf)
	gzw.Write([]byte(str))
	gzw.Close()
	return buf.Bytes()
}
