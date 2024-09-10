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

	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"
)

// EmbeddingModel creates a new instance of the named embedding model.
// Example name: "embedding-001" or "models/embedding-001".
func (c *Client) EmbeddingModel(name string) *EmbeddingModel {
	return &EmbeddingModel{
		c:        c,
		name:     name,
		fullName: fullModelName(name),
	}
}

// EmbeddingModel is a model that computes embeddings.
// Create one with [Client.EmbeddingModel].
type EmbeddingModel struct {
	c        *Client
	name     string
	fullName string
	// TaskType describes how the embedding will be used.
	TaskType TaskType
}

// Name returns the name of the EmbeddingModel.
func (m *EmbeddingModel) Name() string {
	return m.name
}

// EmbedContent returns an embedding for the list of parts.
func (m *EmbeddingModel) EmbedContent(ctx context.Context, parts ...Part) (*EmbedContentResponse, error) {
	return m.EmbedContentWithTitle(ctx, "", parts...)
}

// EmbedContentWithTitle returns an embedding for the list of parts.
// If the given title is non-empty, it is passed to the model and
// the task type is set to TaskTypeRetrievalDocument.
func (m *EmbeddingModel) EmbedContentWithTitle(ctx context.Context, title string, parts ...Part) (*EmbedContentResponse, error) {
	req := newEmbedContentRequest(m.fullName, m.TaskType, title, parts)
	res, err := m.c.gc.EmbedContent(ctx, req)
	if err != nil {
		return nil, err
	}
	return (EmbedContentResponse{}).fromProto(res), nil
}

func newEmbedContentRequest(model string, tt TaskType, title string, parts []Part) *pb.EmbedContentRequest {
	req := &pb.EmbedContentRequest{
		Model:   model,
		Content: NewUserContent(parts...).toProto(),
	}
	// A non-empty title overrides the task type.
	if title != "" {
		req.Title = &title
		tt = TaskTypeRetrievalDocument
	}
	if tt != TaskTypeUnspecified {
		taskType := pb.TaskType(tt)
		req.TaskType = &taskType
	}
	debugPrint(req)
	return req
}

// An EmbeddingBatch holds a collection of embedding requests.
type EmbeddingBatch struct {
	tt  TaskType
	req *pb.BatchEmbedContentsRequest
}

// NewBatch returns a new, empty EmbeddingBatch with the same TaskType as the model.
// Make multiple calls to [EmbeddingBatch.AddContent] or [EmbeddingBatch.AddContentWithTitle].
// Then pass the EmbeddingBatch to [EmbeddingModel.BatchEmbedContents] to get
// all the embeddings in a single call to the model.
func (m *EmbeddingModel) NewBatch() *EmbeddingBatch {
	return &EmbeddingBatch{
		tt: m.TaskType,
		req: &pb.BatchEmbedContentsRequest{
			Model: m.fullName,
		},
	}
}

// AddContent adds a content to the batch.
func (b *EmbeddingBatch) AddContent(parts ...Part) *EmbeddingBatch {
	b.AddContentWithTitle("", parts...)
	return b
}

// AddContent adds a content to the batch with a title.
func (b *EmbeddingBatch) AddContentWithTitle(title string, parts ...Part) *EmbeddingBatch {
	b.req.Requests = append(b.req.Requests, newEmbedContentRequest(b.req.Model, b.tt, title, parts))
	return b
}

// BatchEmbedContents returns the embeddings for all the contents in the batch.
func (m *EmbeddingModel) BatchEmbedContents(ctx context.Context, b *EmbeddingBatch) (*BatchEmbedContentsResponse, error) {
	res, err := m.c.gc.BatchEmbedContents(ctx, b.req)
	if err != nil {
		return nil, err
	}
	return (BatchEmbedContentsResponse{}).fromProto(res), nil
}

// Info returns information about the model.
func (m *EmbeddingModel) Info(ctx context.Context) (*ModelInfo, error) {
	return m.c.modelInfo(ctx, m.fullName)
}
