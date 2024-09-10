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

// For the following go:generate line to work, install the protoveener tool:
//    git clone https://github.com/googleapis/google-cloud-go
//    cd google-cloud-go
//    go install ./internal/protoveneer/cmd/protoveneer
//
//go:generate ./generate.sh

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

	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// A Client is a Google generative AI client.
type Client struct {
	gc *gl.GenerativeClient
	mc *gl.ModelClient
	fc *gl.FileClient
	cc *gl.CacheClient
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
	gc, err := gl.NewGenerativeRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating generative client: %w", err)
	}
	mc, err := gl.NewModelRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating model client: %w", err)
	}
	fc, err := gl.NewFileRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating file client: %w", err)
	}

	// Workaround for https://github.com/google/generative-ai-go/issues/151
	optsForCache := removeHTTPClientOption(opts)
	cc, err := gl.NewCacheClient(ctx, optsForCache...)
	if err != nil {
		return nil, fmt.Errorf("creating cache client: %w", err)
	}

	ds, err := gld.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %w", err)
	}

	kvs := []string{"gccl", "v" + internal.Version, "genai-go", internal.Version}
	if a, ok := optionOfType[*clientInfo](opts); ok {
		kvs = append(kvs, a.key, a.value)
	}
	gc.SetGoogleClientInfo(kvs...)
	mc.SetGoogleClientInfo(kvs...)
	fc.SetGoogleClientInfo(kvs...)

	return &Client{gc, mc, fc, cc, ds}, nil
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

		case "option.withHTTPClient",
			"option.withTokenSource",
			"option.withCredentialsFile",
			"option.withCredentialsJSON":
			return true
		}
	}
	return false
}

// removeHTTPClientOption removes option.withHTTPClient from the given list
// of options, if it exists; it returns the new (filtered) list.
func removeHTTPClientOption(opts []option.ClientOption) []option.ClientOption {
	var newOpts []option.ClientOption
	for _, opt := range opts {
		ts := reflect.ValueOf(opt).Type().String()
		if ts != "option.withHTTPClient" {
			newOpts = append(newOpts, opt)
		}
	}
	return newOpts
}

// Close closes the client.
func (c *Client) Close() error {
	return errors.Join(c.gc.Close(), c.mc.Close(), c.fc.Close())
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
	// The name of the CachedContent to use.
	// Must have already been created with [Client.CreateCachedContent].
	CachedContentName string
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
	content := NewUserContent(parts...)
	req, err := m.newGenerateContentRequest(content)
	if err != nil {
		return nil, err
	}
	res, err := m.c.gc.GenerateContent(ctx, req)
	if err != nil {
		return nil, err
	}
	return protoToResponse(res)
}

// GenerateContentStream returns an iterator that enumerates responses.
func (m *GenerativeModel) GenerateContentStream(ctx context.Context, parts ...Part) *GenerateContentResponseIterator {
	iter := &GenerateContentResponseIterator{}
	req, err := m.newGenerateContentRequest(NewUserContent(parts...))
	if err != nil {
		iter.err = err
	} else {
		iter.sc, iter.err = m.c.gc.StreamGenerateContent(ctx, req)
	}
	return iter
}

func (m *GenerativeModel) generateContent(ctx context.Context, req *pb.GenerateContentRequest) (*GenerateContentResponse, error) {
	streamClient, err := m.c.gc.StreamGenerateContent(ctx, req)
	iter := &GenerateContentResponseIterator{
		sc:  streamClient,
		err: err,
	}
	for {
		_, err := iter.Next()
		if err == iterator.Done {
			return iter.MergedResponse(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (m *GenerativeModel) newGenerateContentRequest(contents ...*Content) (*pb.GenerateContentRequest, error) {
	return pvCatchPanic(func() *pb.GenerateContentRequest {
		var cc *string
		if m.CachedContentName != "" {
			cc = &m.CachedContentName
		}
		req := &pb.GenerateContentRequest{
			Model:             m.fullName,
			Contents:          transformSlice(contents, (*Content).toProto),
			SafetySettings:    transformSlice(m.SafetySettings, (*SafetySetting).toProto),
			Tools:             transformSlice(m.Tools, (*Tool).toProto),
			ToolConfig:        m.ToolConfig.toProto(),
			GenerationConfig:  m.GenerationConfig.toProto(),
			SystemInstruction: m.SystemInstruction.toProto(),
			CachedContent:     cc,
		}
		debugPrint(req)
		return req
	})
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
	gcp, err := fromProto[GenerateContentResponse](resp)
	if err != nil {
		return nil, err
	}
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

// MergedResponse returns the result of combining all the streamed responses seen so far.
// After iteration completes, the merged response should match the response obtained without streaming
// (that is, if [GenerativeModel.GenerateContent] were called).
func (iter *GenerateContentResponseIterator) MergedResponse() *GenerateContentResponse {
	return iter.merged
}

// CountTokens counts the number of tokens in the content.
func (m *GenerativeModel) CountTokens(ctx context.Context, parts ...Part) (*CountTokensResponse, error) {
	req, err := m.newCountTokensRequest(NewUserContent(parts...))
	if err != nil {
		return nil, err
	}
	res, err := m.c.gc.CountTokens(ctx, req)
	if err != nil {
		return nil, err
	}
	return fromProto[CountTokensResponse](res)
}

func (m *GenerativeModel) newCountTokensRequest(contents ...*Content) (*pb.CountTokensRequest, error) {
	gcr, err := m.newGenerateContentRequest(contents...)
	if err != nil {
		return nil, err
	}
	req := &pb.CountTokensRequest{
		Model:                  m.fullName,
		GenerateContentRequest: gcr,
	}
	debugPrint(req)
	return req, nil
}

// Info returns information about the model.
func (m *GenerativeModel) Info(ctx context.Context) (*ModelInfo, error) {
	return m.c.modelInfo(ctx, m.fullName)
}

func (c *Client) modelInfo(ctx context.Context, fullName string) (*ModelInfo, error) {
	req := &pb.GetModelRequest{Name: fullName}
	debugPrint(req)
	res, err := c.mc.GetModel(ctx, req)
	if err != nil {
		return nil, err
	}
	return fromProto[ModelInfo](res)
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

// transformSlice applies f to each element of from and returns
// a new slice with the results.
func transformSlice[From, To any](from []From, f func(From) To) []To {
	if from == nil {
		return nil
	}
	to := make([]To, len(from))
	for i, e := range from {
		to[i] = f(e)
	}
	return to
}

func fromProto[V interface{ fromProto(P) *V }, P any](p P) (*V, error) {
	var v V
	return pvCatchPanic(func() *V { return v.fromProto(p) })
}
