// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package backend defines abstractions and interfaces for AI model backends.
package backend

import (
	"context"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

// Role represents the author of a message.
type Role string

const (
	RoleUser  Role = "user"
	RoleModel Role = "model"
)

// Part represents a single component of a message.
// It can be text, a function call, or a function response.
type Part struct {
	Text             string            `json:"text,omitempty"`
	Thought          bool              `json:"thought,omitempty"`
	ThoughtSignature []byte            `json:"thoughtSignature,omitempty"`
	FunctionCall     *FunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *FunctionResponse `json:"functionResponse,omitempty"`
}

// FunctionCall represents a request from the model to execute a tool.
type FunctionCall struct {
	ID   string         `json:"id,omitempty"`
	Args map[string]any `json:"args,omitempty"`
	Name string         `json:"name"`
}

// FunctionResponse represents the result of executing a tool.
type FunctionResponse struct {
	ID       string         `json:"id,omitempty"`
	Response map[string]any `json:"response,omitempty"`
	Name     string         `json:"name"`
}

// Message represents a single turn in a conversation.
type Message struct {
	Parts []Part `json:"parts,omitempty"`
	Role  Role   `json:"role,omitempty"`
}

// FunctionDeclaration describes a tool that the model can call.
type FunctionDeclaration struct {
	Description          string             `json:"description,omitempty"`
	Name                 string             `json:"name"`
	ParametersJSONSchema *jsonschema.Schema `json:"parametersJsonSchema,omitempty"`
	ResponseJSONSchema   *jsonschema.Schema `json:"responseJsonSchema,omitempty"`
}

// Tool represents a collection of function declarations.
type Tool struct {
	FunctionDeclarations []*FunctionDeclaration `json:"functionDeclarations,omitempty"`
}

// GenerateConfig contains parameters for content generation.
type GenerateConfig struct {
	SystemInstruction *Message      `json:"systemInstruction,omitempty"`
	Temperature       *float32      `json:"temperature,omitempty"`
	Tools             []*Tool       `json:"tools,omitempty"`
	ThinkingLevel     ThinkingLevel `json:"thinkingLevel,omitempty"`
	IncludeThoughts   bool          `json:"includeThoughts,omitempty"`
}

// ThinkingLevel specifies how much effort the model should spend on reasoning.
type ThinkingLevel int

const (
	ThinkingLevelMinimal ThinkingLevel = iota
	ThinkingLevelLow
	ThinkingLevelMedium
	ThinkingLevelHigh
)

// UsageMetadata contains token usage statistics for a generation request.
type UsageMetadata struct {
	InputTokens          int `json:"inputTokens,omitempty"`
	OutputTokens         int `json:"outputTokens,omitempty"`
	OutputThoughtsTokens int `json:"outputThoughtsTokens,omitempty"`
}

// GenerateResponse represents the model's response to a generation request.
type GenerateResponse struct {
	Parts         []Part         `json:"parts,omitempty"`
	UsageMetadata *UsageMetadata `json:"usageMetadata,omitempty"`
}

type Client interface {
	GenerateContent(ctx context.Context, model string, cfg *GenerateConfig, history []*Message) (*GenerateResponse, error)
}

// ModelCategory represents the class of model to use.
type ModelCategory string

const (
	// BestExpensiveModel is the most capable, but potentially slower and more expensive model.
	BestExpensiveModel ModelCategory = "best-expensive"
	// GoodBalancedModel is a fast, cost-effective model with good capabilities.
	GoodBalancedModel ModelCategory = "good-balanced"
)

// Provider represents an LLM provider (e.g., Gemini, Claude).
type Provider interface {
	// Client returns a client for the given context, or an error if authentication fails.
	Client(ctx context.Context) (Client, error)
	// Models returns a list of model names supported by this provider.
	Models(ctx context.Context) ([]string, error)
	// DefaultModel returns the provider-specific model name for a given category.
	ResolveModels(category ModelCategory) []string
}

// RetryError indicates that the request failed but should be retried.
type RetryError struct {
	Delay         time.Duration
	IsExponential bool
	Err           error
}

func (e *RetryError) Error() string {
	return e.Err.Error()
}

func (e *RetryError) Unwrap() error {
	return e.Err
}

// OutputTokenOverflowError indicates that the model reached its output token limit.
type OutputTokenOverflowError struct {
	Err error
}

func (e *OutputTokenOverflowError) Error() string {
	return e.Err.Error()
}

func (e *OutputTokenOverflowError) Unwrap() error {
	return e.Err
}

// InputTokenOverflowError indicates that the model reached its input token limit.
type InputTokenOverflowError struct {
	Err error
}

func (e *InputTokenOverflowError) Error() string {
	return e.Err.Error()
}

func (e *InputTokenOverflowError) Unwrap() error {
	return e.Err
}
