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
	"fmt"

	pb "cloud.google.com/go/ai/generativelanguage/apiv1beta/generativelanguagepb"
)

const (
	roleUser  = "user"
	roleModel = "model"
)

// A Part is a piece of model content.
// A Part can be one of the following types:
//   - Text
//   - Blob
//   - FunctionCall
//   - FunctionResponse
//   - ExecutableCode
//   - CodeExecutionResult
type Part interface {
	toPart() *pb.Part
}

func partToProto(p Part) *pb.Part {
	if p == nil {
		return nil
	}
	return p.toPart()
}

func partFromProto(p *pb.Part) Part {
	switch d := p.Data.(type) {
	case *pb.Part_Text:
		return Text(d.Text)
	case *pb.Part_InlineData:
		return Blob{
			MIMEType: d.InlineData.MimeType,
			Data:     d.InlineData.Data,
		}
	case *pb.Part_FunctionCall:
		return *(FunctionCall{}).fromProto(d.FunctionCall)

	case *pb.Part_FunctionResponse:
		panic("FunctionResponse unimplemented")

	case *pb.Part_ExecutableCode:
		return (ExecutableCode{}).fromProto(d.ExecutableCode)
	case *pb.Part_CodeExecutionResult:
		return (CodeExecutionResult{}).fromProto(d.CodeExecutionResult)
	default:
		panic(fmt.Errorf("unknown Part.Data type %T", p.Data))
	}
}

// A Text is a piece of text, like a question or phrase.
type Text string

func (t Text) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_Text{Text: string(t)},
	}
}

func (b Blob) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_InlineData{
			InlineData: b.toProto(),
		},
	}
}

// ImageData is a convenience function for creating an image
// Blob for input to a model.
// The format should be the second part of the MIME type, after "image/".
// For example, for a PNG image, pass "png".
func ImageData(format string, data []byte) Blob {
	return Blob{
		MIMEType: "image/" + format,
		Data:     data,
	}
}

func (f FunctionCall) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_FunctionCall{
			FunctionCall: f.toProto(),
		},
	}
}

func (f FunctionResponse) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_FunctionResponse{
			FunctionResponse: f.toProto(),
		},
	}
}

func (fd FileData) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_FileData{
			FileData: fd.toProto(),
		},
	}
}

func (ec ExecutableCode) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_ExecutableCode{
			ExecutableCode: ec.toProto(),
		},
	}
}

func (c CodeExecutionResult) toPart() *pb.Part {
	return &pb.Part{
		Data: &pb.Part_CodeExecutionResult{
			CodeExecutionResult: c.toProto(),
		},
	}
}

// Ptr returns a pointer to its argument.
// It can be used to initialize pointer fields:
//
//	model.Temperature = genai.Ptr[float32](0.1)
func Ptr[T any](t T) *T { return &t }

// SetCandidateCount sets the CandidateCount field.
func (c *GenerationConfig) SetCandidateCount(x int32) { c.CandidateCount = &x }

// SetMaxOutputTokens sets the MaxOutputTokens field.
func (c *GenerationConfig) SetMaxOutputTokens(x int32) { c.MaxOutputTokens = &x }

// SetTemperature sets the Temperature field.
func (c *GenerationConfig) SetTemperature(x float32) { c.Temperature = &x }

// SetTopP sets the TopP field.
func (c *GenerationConfig) SetTopP(x float32) { c.TopP = &x }

// SetTopK sets the TopK field.
func (c *GenerationConfig) SetTopK(x int32) { c.TopK = &x }

// FunctionCalls return all the FunctionCall parts in the candidate.
func (c *Candidate) FunctionCalls() []FunctionCall {
	if c.Content == nil {
		return nil
	}
	var fcs []FunctionCall
	for _, p := range c.Content.Parts {
		if fc, ok := p.(FunctionCall); ok {
			fcs = append(fcs, fc)
		}
	}
	return fcs
}

// NewUserContent returns a *Content with a "user" role set and one or more
// parts.
func NewUserContent(parts ...Part) *Content {
	content := &Content{Role: roleUser, Parts: []Part{}}
	for _, part := range parts {
		content.Parts = append(content.Parts, part)
	}
	return content
}
