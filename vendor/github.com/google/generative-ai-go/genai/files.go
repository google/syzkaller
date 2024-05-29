// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package genai

//go:generate ../devtools/generate_discovery_client.sh

import (
	"context"
	"io"
	"strings"

	gl "cloud.google.com/go/ai/generativelanguage/apiv1beta"
	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"
	gld "github.com/google/generative-ai-go/genai/internal/generativelanguage/v1beta" // discovery client
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// UploadFileOptions are options for [Client.UploadFile].
type UploadFileOptions struct {
	DisplayName string // a more readable name for the file
	MIMEType    string // the MIME type of the file; if omitted, it will be inferred
}

// UploadFile copies the contents of the given io.Reader to file storage associated
// with the service, and returns information about the resulting file.
//
// The name may be empty, in which case a unique name will be generated.
// Otherwise, it can contain up to 40 characters that are lowercase
// alphanumeric or dashes (-), not starting or ending with a dash.
// The string "files/" is prepended to the name if it does not contain a '/'.
//
// Use the returned file's URI field with a [FileData] Part to use it for generation.
//
// It is an error to upload a file that already exists.
func (c *Client) UploadFile(ctx context.Context, name string, r io.Reader, opts *UploadFileOptions) (*File, error) {
	if name != "" {
		name = userNameToServiceName(name)
	}
	req := &gld.CreateFileRequest{
		File: &gld.File{Name: name},
	}
	if opts != nil && opts.DisplayName != "" {
		req.File.DisplayName = opts.DisplayName
	}
	call := c.ds.Media.Upload(req)
	var mopts []googleapi.MediaOption
	if opts != nil && opts.MIMEType != "" {
		mopts = append(mopts, googleapi.ContentType(opts.MIMEType))
	}
	call.Media(r, mopts...)
	res, err := call.Do()
	if err != nil {
		return nil, err
	}
	// Don't return the result, because it contains a file as represented by the
	// discovery client and we'd have to write code to convert it to this package's
	// File type.
	// Instead, make a GetFile call to get the proto file, which our generated code can convert.
	return c.GetFile(ctx, res.File.Name)
}

// GetFile returns the named file.
func (c *Client) GetFile(ctx context.Context, name string) (*File, error) {
	pf, err := c.fc.GetFile(ctx, &pb.GetFileRequest{Name: userNameToServiceName(name)})
	if err != nil {
		return nil, err
	}
	return (File{}).fromProto(pf), nil
}

// DeleteFile deletes the file with the given name.
// It is an error to delete a file that does not exist.
func (c *Client) DeleteFile(ctx context.Context, name string) error {
	return c.fc.DeleteFile(ctx, &pb.DeleteFileRequest{Name: userNameToServiceName(name)})
}

// userNameToServiceName converts a name supplied by the user to a name required by the service.
func userNameToServiceName(name string) string {
	if strings.ContainsRune(name, '/') {
		return name
	}
	return "files/" + name
}

// ListFiles returns an iterator over the uploaded files.
func (c *Client) ListFiles(ctx context.Context) *FileIterator {
	return &FileIterator{
		it: c.fc.ListFiles(ctx, &pb.ListFilesRequest{}),
	}
}

// A FileIterator iterates over Files.
type FileIterator struct {
	it *gl.FileIterator
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *FileIterator) Next() (*File, error) {
	m, err := it.it.Next()
	if err != nil {
		return nil, err
	}
	return (File{}).fromProto(m), nil
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *FileIterator) PageInfo() *iterator.PageInfo {
	return it.it.PageInfo()
}
