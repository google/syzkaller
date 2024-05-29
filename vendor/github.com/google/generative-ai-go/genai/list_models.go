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

import (
	"context"

	gl "cloud.google.com/go/ai/generativelanguage/apiv1beta"
	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"

	"google.golang.org/api/iterator"
)

func (c *Client) ListModels(ctx context.Context) *ModelInfoIterator {
	return &ModelInfoIterator{
		it: c.mc.ListModels(ctx, &pb.ListModelsRequest{}),
	}
}

// A ModelInfoIterator iterates over Models.
type ModelInfoIterator struct {
	it *gl.ModelIterator
}

// Next returns the next result. Its second return value is iterator.Done if there are no more
// results. Once Next returns Done, all subsequent calls will return Done.
func (it *ModelInfoIterator) Next() (*ModelInfo, error) {
	m, err := it.it.Next()
	if err != nil {
		return nil, err
	}
	return (ModelInfo{}).fromProto(m), nil
}

// PageInfo supports pagination. See the google.golang.org/api/iterator package for details.
func (it *ModelInfoIterator) PageInfo() *iterator.PageInfo {
	return it.it.PageInfo()
}
