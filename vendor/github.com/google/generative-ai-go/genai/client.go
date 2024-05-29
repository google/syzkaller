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

// For the following go:generate line to work, do the following:
// Install the protoveener tool:
//    git clone https://github.com/googleapis/google-cloud-go
//    cd google-cloud-go
//    go install ./internal/protoveneer/cmd/protoveneer
//
// Set the environment variable GOOGLE_CLOUD_GO to the path to the above repo on your machine.
// For example:
//     export GOOGLE_CLOUD_GO=$HOME/repos/google-cloud-go

//go:generate protoveneer -license license.txt config.yaml $GOOGLE_CLOUD_GO/ai/generativelanguage/apiv1beta/generativelanguagepb

package genai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	gl "cloud.google.com/go/ai/generativelanguage/apiv1beta"
	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"
	"github.com/google/generative-ai-go/genai/internal"
	gld "github.com/google/generative-ai-go/genai/internal/generativelanguage/v1beta" // discovery client

	"github.com/google/generative-ai-go/internal/support"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// A Client is a Google generative AI client.
type Client struct {
	c  *gl.GenerativeClient
	mc *gl.ModelClient
	fc *gl.FileClient
	ds *gld.Service
}

// NewClient creates a new Google generative AI client.
//
// Clients should be reused instead of created as needed. The methods of Client
// are safe for concurrent use by multiple goroutines.
//
// You may configure the client by passing in options from the [google.golang.org/api/option]
// package.
func NewClient(ctx context.Context, opts ...option.ClientOption) (*Client, error) {
	if !hasAuthOption(opts) {
		return nil, errors.New(`You need an auth option to use this client.
for an API Key: Visit https://ai.google.dev to get one, put it in an environment variable like GEMINI_API_KEY,
then pass it as an option:
    genai.NewClient(ctx, option.WithAPIKey(os.Getenv("GEMINI_API_KEY")))
(If you're doing that already, then maybe the environment variable is empty or unset.)
Import the option package as "google.golang.org/api/option".`)
	}
	c, err := gl.NewGenerativeRESTClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	mc, err := gl.NewModelRESTClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	fc, err := gl.NewFileRESTClient(ctx, opts...)
	if err != nil {
		return nil, err
	}
	ds, err := gld.NewService(ctx, opts...)
	if err != nil {
		return nil, err
	}
	c.SetGoogleClientInfo("gccl", "v"+internal.Version, "genai-go", internal.Version)
	return &Client{c, mc, fc, ds}, nil
}

// hasAuthOption reports whether an authentication-related option was provided.
//
// There is no good way to make these checks, because the types of the options
// are unexported, and the struct that they populates is in an internal package.
func hasAuthOption(opts []option.ClientOption) bool {
	for _, opt := range opts {
		v := reflect.ValueOf(opt)
		ts := v.Type().String()

		switch ts {
		case "option.withAPIKey":
			return v.String() != ""

		case "option.withHttpClient",
			"option.withTokenSource",
			"option.withCredentialsFile",
			"option.withCredentialsJSON":
			return true
		}
	}
	return false
}

// Close closes the client.
func (c *Client) Close() error {
	return errors.Join(c.c.Close(), c.mc.Close(), c.fc.Close())
}

// GenerativeModel is a model that can generate text.
// Create one with [Client.GenerativeModel], then configure
// it by setting the exported fields.
type GenerativeModel struct {
	c        *Client
	fullName string

	GenerationConfig
	SafetySettings []*SafetySetting
	Tools          []*Tool
	ToolConfig     *ToolConfig // configuration for tools
	// SystemInstruction (also known as "system prompt") is a more forceful prompt to the model.
	// The model will adhere the instructions more strongly than if they appeared in a normal prompt.
	SystemInstruction *Content
}

// GenerativeModel creates a new instance of the named generative model.
// For instance, "gemini-1.0-pro" or "models/gemini-1.0-pro".
//
// To access a tuned model named NAME, pass "tunedModels/NAME".
func (c *Client) GenerativeModel(name string) *GenerativeModel {
	return &GenerativeModel{
		c:        c,
		fullName: fullModelName(name),
	}
}

func fullModelName(name string) string {
	if strings.ContainsRune(name, '/') {
		return name
	}
	return "models/" + name
}

// GenerateContent produces a single request and response.
func (m *GenerativeModel) GenerateContent(ctx context.Context, parts ...Part) (*GenerateContentResponse, error) {
	content := newUserContent(parts)
	req := m.newGenerateContentRequest(content)
	res, err := m.c.c.GenerateContent(ctx, req)
	if err != nil {
		return nil, err
	}
	return protoToResponse(res)
}

// GenerateContentStream returns an iterator that enumerates responses.
func (m *GenerativeModel) GenerateContentStream(ctx context.Context, parts ...Part) *GenerateContentResponseIterator {
	streamClient, err := m.c.c.StreamGenerateContent(ctx, m.newGenerateContentRequest(newUserContent(parts)))
	return &GenerateContentResponseIterator{
		sc:  streamClient,
		err: err,
	}
}

func (m *GenerativeModel) generateContent(ctx context.Context, req *pb.GenerateContentRequest) (*GenerateContentResponse, error) {
	streamClient, err := m.c.c.StreamGenerateContent(ctx, req)
	iter := &GenerateContentResponseIterator{
		sc:  streamClient,
		err: err,
	}
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			return iter.merged, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (m *GenerativeModel) newGenerateContentRequest(contents ...*Content) *pb.GenerateContentRequest {
	return &pb.GenerateContentRequest{
		Model:             m.fullName,
		Contents:          support.TransformSlice(contents, (*Content).toProto),
		SafetySettings:    support.TransformSlice(m.SafetySettings, (*SafetySetting).toProto),
		Tools:             support.TransformSlice(m.Tools, (*Tool).toProto),
		ToolConfig:        m.ToolConfig.toProto(),
		GenerationConfig:  m.GenerationConfig.toProto(),
		SystemInstruction: m.SystemInstruction.toProto(),
	}
}

func newUserContent(parts []Part) *Content {
	return &Content{Role: roleUser, Parts: parts}
}

// GenerateContentResponseIterator is an iterator over GnerateContentResponse.
type GenerateContentResponseIterator struct {
	sc     pb.GenerativeService_StreamGenerateContentClient
	err    error
	merged *GenerateContentResponse
	cs     *ChatSession
}

// Next returns the next response.
func (iter *GenerateContentResponseIterator) Next() (*GenerateContentResponse, error) {
	if iter.err != nil {
		return nil, iter.err
	}
	resp, err := iter.sc.Recv()
	iter.err = err
	if err == io.EOF {
		if iter.cs != nil && iter.merged != nil {
			iter.cs.addToHistory(iter.merged.Candidates)
		}
		return nil, iterator.Done
	}
	if err != nil {
		return nil, err
	}
	gcp, err := protoToResponse(resp)
	if err != nil {
		iter.err = err
		return nil, err
	}
	// Merge this response in with the ones we've already seen.
	iter.merged = joinResponses(iter.merged, gcp)
	// If this is part of a ChatSession, remember the response for the history.
	return gcp, nil
}

func protoToResponse(resp *pb.GenerateContentResponse) (*GenerateContentResponse, error) {
	gcp := (GenerateContentResponse{}).fromProto(resp)
	if gcp == nil {
		return nil, errors.New("empty response from model")
	}
	// Assume a non-nil PromptFeedback is an error.
	// TODO: confirm.
	if gcp.PromptFeedback != nil && gcp.PromptFeedback.BlockReason != BlockReasonUnspecified {
		return nil, &BlockedError{PromptFeedback: gcp.PromptFeedback}
	}

	// If any candidate is blocked, error.
	// TODO: is this too harsh?
	for _, c := range gcp.Candidates {
		if c.FinishReason == FinishReasonSafety || c.FinishReason == FinishReasonRecitation {
			return nil, &BlockedError{Candidate: c}
		}
	}
	return gcp, nil
}

// CountTokens counts the number of tokens in the content.
func (m *GenerativeModel) CountTokens(ctx context.Context, parts ...Part) (*CountTokensResponse, error) {
	req := m.newCountTokensRequest(newUserContent(parts))
	res, err := m.c.c.CountTokens(ctx, req)
	if err != nil {
		return nil, err
	}

	return (CountTokensResponse{}).fromProto(res), nil
}

func (m *GenerativeModel) newCountTokensRequest(contents ...*Content) *pb.CountTokensRequest {
	return &pb.CountTokensRequest{
		Model:    m.fullName,
		Contents: support.TransformSlice(contents, (*Content).toProto),
	}
}

// Info returns information about the model.
func (m *GenerativeModel) Info(ctx context.Context) (*ModelInfo, error) {
	return m.c.modelInfo(ctx, m.fullName)
}

func (c *Client) modelInfo(ctx context.Context, fullName string) (*ModelInfo, error) {
	req := &pb.GetModelRequest{Name: fullName}
	res, err := c.mc.GetModel(ctx, req)
	if err != nil {
		return nil, err
	}
	return (ModelInfo{}).fromProto(res), nil
}

// A BlockedError indicates that the model's response was blocked.
// There can be two underlying causes: the prompt or a candidate response.
type BlockedError struct {
	// If non-nil, the model's response was blocked.
	// Consult the FinishReason field for details.
	Candidate *Candidate

	// If non-nil, there was a problem with the prompt.
	PromptFeedback *PromptFeedback
}

func (e *BlockedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "blocked: ")
	if e.Candidate != nil {
		fmt.Fprintf(&b, "candidate: %s", e.Candidate.FinishReason)
	}
	if e.PromptFeedback != nil {
		if e.Candidate != nil {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "prompt: %v", e.PromptFeedback.BlockReason)
	}
	return b.String()
}

// joinResponses merges the two responses, which should be the result of a streaming call.
// The first argument is modified.
func joinResponses(dest, src *GenerateContentResponse) *GenerateContentResponse {
	if dest == nil {
		return src
	}
	dest.Candidates = joinCandidateLists(dest.Candidates, src.Candidates)
	// Keep dest.PromptFeedback.
	// TODO: Take the last UsageMetadata.
	return dest
}

func joinCandidateLists(dest, src []*Candidate) []*Candidate {
	indexToSrcCandidate := map[int32]*Candidate{}
	for _, s := range src {
		indexToSrcCandidate[s.Index] = s
	}
	for _, d := range dest {
		s := indexToSrcCandidate[d.Index]
		if s != nil {
			d.Content = joinContent(d.Content, s.Content)
			// Take the last of these.
			d.FinishReason = s.FinishReason
			// d.FinishMessage = s.FinishMessage
			d.SafetyRatings = s.SafetyRatings
			d.CitationMetadata = joinCitationMetadata(d.CitationMetadata, s.CitationMetadata)
		}
	}
	return dest
}

func joinCitationMetadata(dest, src *CitationMetadata) *CitationMetadata {
	if dest == nil {
		return src
	}
	if src == nil {
		return dest
	}
	dest.CitationSources = append(dest.CitationSources, src.CitationSources...)
	return dest
}

func joinContent(dest, src *Content) *Content {
	if dest == nil {
		return src
	}
	if src == nil {
		return dest
	}
	// Assume roles are the same.
	dest.Parts = joinParts(dest.Parts, src.Parts)
	return dest
}

func joinParts(dest, src []Part) []Part {
	return mergeTexts(append(dest, src...))
}

func mergeTexts(in []Part) []Part {
	var out []Part
	i := 0
	for i < len(in) {
		if t, ok := in[i].(Text); ok {
			texts := []string{string(t)}
			var j int
			for j = i + 1; j < len(in); j++ {
				if t, ok := in[j].(Text); ok {
					texts = append(texts, string(t))
				} else {
					break
				}
			}
			// j is just after the last Text.
			out = append(out, Text(strings.Join(texts, "")))
			i = j
		} else {
			out = append(out, in[i])
			i++
		}
	}
	return out
}
