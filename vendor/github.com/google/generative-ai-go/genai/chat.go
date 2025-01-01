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
)

// A ChatSession provides interactive chat.
type ChatSession struct {
	m       *GenerativeModel
	History []*Content
}

// StartChat starts a chat session.
func (m *GenerativeModel) StartChat() *ChatSession {
	return &ChatSession{m: m}
}

// SendMessage sends a request to the model as part of a chat session.
func (cs *ChatSession) SendMessage(ctx context.Context, parts ...Part) (*GenerateContentResponse, error) {
	// Call the underlying client with the entire history plus the argument Content.
	cs.History = append(cs.History, NewUserContent(parts...))
	req, err := cs.m.newGenerateContentRequest(cs.History...)
	if err != nil {
		return nil, err
	}
	req.GenerationConfig.CandidateCount = Ptr[int32](1)
	resp, err := cs.m.generateContent(ctx, req)
	if err != nil {
		return nil, err
	}
	cs.addToHistory(resp.Candidates)
	return resp, nil
}

// SendMessageStream is like SendMessage, but with a streaming request.
func (cs *ChatSession) SendMessageStream(ctx context.Context, parts ...Part) *GenerateContentResponseIterator {
	cs.History = append(cs.History, NewUserContent(parts...))
	req, err := cs.m.newGenerateContentRequest(cs.History...)
	if err != nil {
		return &GenerateContentResponseIterator{err: err}
	}
	req.GenerationConfig.CandidateCount = Ptr[int32](1)
	streamClient, err := cs.m.c.gc.StreamGenerateContent(ctx, req)
	return &GenerateContentResponseIterator{
		sc:  streamClient,
		err: err,
		cs:  cs,
	}
}

// By default, use the first candidate for history. The user can modify that if they want.
func (cs *ChatSession) addToHistory(cands []*Candidate) bool {
	if len(cands) > 0 {
		c := cands[0].Content
		if c == nil {
			return false
		}
		c.Role = roleModel
		cs.History = append(cs.History, copySanitizedModelContent(c))
		return true
	}
	return false
}

// copySanitizedModelContent creates a (shallow) copy of c with role set to
// model and empty text parts removed.
func copySanitizedModelContent(c *Content) *Content {
	newc := &Content{Role: roleModel}
	for _, part := range c.Parts {
		if t, ok := part.(Text); !ok || len(string(t)) > 0 {
			newc.Parts = append(newc.Parts, part)
		}
	}
	return newc
}
