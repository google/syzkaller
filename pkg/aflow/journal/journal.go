// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package journal

import (
	"fmt"
	"time"
)

type Journal struct {
	Span

	current *Span
	onEvent OnEvent
	now     Now
}

type OnEvent func(*Event) error
type Now func() time.Time

type Span struct {
	Start  *Event
	End    *Event
	Parent *Span
	Nested []*Span
}

type Event struct {
	FlowStart   *EventFlowStart   `json:"flow_start,omitempty"`
	FlowEnd     *EventFlowEnd     `json:"flow_end,omitempty"`
	ActionStart *EventActionStart `json:"action_start,omitempty"`
	ActionEnd   *EventActionEnd   `json:"action_end,omitempty"`
	AgentStart  *EventAgentStart  `json:"agent_start,omitempty"`
	AgentEnd    *EventAgentEnd    `json:"agent_end,omitempty"`
	LLMRequest  *EventLLMRequest  `json:"llm_request,omitempty"`
	LLMResponse *EventLLMResponse `json:"llm_response,omitempty"`
	ToolCall    *EventToolCall    `json:"tool_call,omitempty"`
	ToolResult  *EventToolResult  `json:"tool_result,omitempty"`

	Timestamp time.Time `json:"timestamp"`

	Nesting int `json:"-"`

	live bool
}

type SpanStart struct {
	Name string `json:"name,omitempty"`
}

type SpanEnd struct {
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
	NestedError bool          `json:"nested_error,omitempty"`
}

type EventFlowStart struct {
	SpanStart
	Args map[string]any `json:"args"`
	//!!! add hash, commit, etc
}

type EventFlowEnd struct {
	SpanEnd
	Results map[string]any `json:"results"`
}

type EventActionStart struct {
	SpanStart
	//Args map[string]any `json:"args"`
}

type EventActionEnd struct {
	SpanEnd
	Results map[string]any `json:"results"`
}

type EventAgentStart struct {
	SpanStart
	Instruction string `json:"instruction"`
	Prompt      string `json:"prompt"`
}

type EventAgentEnd struct {
	SpanEnd
	Result   string `json:"result"`
	Thoughts string `json:"thoughts,omitempty"`
}

type EventLLMRequest struct {
	SpanStart
}

type EventLLMResponse struct {
	SpanEnd
}

type EventToolCall struct {
	SpanStart
	Args map[string]any `json:"args"`
}

type EventToolResult struct {
	SpanEnd
	Results map[string]any `json:"results"`
}

func New(events []*Event, onEvent OnEvent, now Now) (*Journal, error) {
	if onEvent == nil {
		onEvent = func(*Event) error {
			return nil
		}
	}
	if now == nil {
		now = time.Now
	}
	j := &Journal{
		onEvent: onEvent,
		now:     now,
	}
	j.current = &j.Span
	for _, ev := range events {
		if _, _, err := j.append(ev); err != nil {
			return nil, err
		}
	}
	j.current = &j.Span
	return j, nil
}

func (j *Journal) Append(body any) (*Span, error) {
	ev, err := j.newEvent(body)
	if err != nil {
		return nil, err
	}
	added, span, err := j.append(ev)
	if err != nil {
		return nil, err
	}
	if added {
		if err := j.onEvent(ev); err != nil {
			return nil, err
		}
	}
	if _, end := ev.startEnd(); end != nil && end.Error != "" {
		if err := j.closeAllOpen(); err != nil {
			return nil, err
		}
	}
	return span, nil
}

func (j *Journal) newEvent(body any) (*Event, error) {
	ev := &Event{
		Timestamp: j.now(),
		live:      true,
	}
	switch body := body.(type) {
	case *EventFlowStart:
		ev.FlowStart = body
	case *EventFlowEnd:
		ev.FlowEnd = body
	case *EventActionStart:
		ev.ActionStart = body
	case *EventActionEnd:
		ev.ActionEnd = body
	case *EventAgentStart:
		ev.AgentStart = body
	case *EventAgentEnd:
		ev.AgentEnd = body
	case *EventLLMRequest:
		ev.LLMRequest = body
	case *EventLLMResponse:
		ev.LLMResponse = body
	case *EventToolCall:
		ev.ToolCall = body
	case *EventToolResult:
		ev.ToolResult = body
	default:
		return nil, fmt.Errorf("bad event type %T", body)
	}
	return ev, nil
}

func (j *Journal) append(ev *Event) (bool, *Span, error) {
	start, end := ev.startEnd()
	if start == nil && end == nil {
		return false, nil, fmt.Errorf("bad event: %+v", *ev)
	}
	/*
		if j.position == nil {
			if start == nil {
				return false, nil, fmt.Errorf("the initial journal event is not start")
			}
			j.Span = &Span{}
			j.position = j.Span
		} else
	*/
	span := j.current
	if start != nil {
		if j.current.Start != nil && j.current.Start.live {
			span := &Span{
				Parent: j.current,
			}
			j.current.Nested = append(j.current.Nested, span)
			j.current = span
		}
		span = j.current
		if j.current.Start != nil {
			if !ev.live || j.current.Start.live {
				//!!! duplicate start event
			}
			//!!! compare events
		} else {
			j.current.Start = ev
		}
		//!!! this must not be done for non-pure func actions
		if ev.live && j.current.End != nil {
			j.current = j.current.Parent
		}
	} else {
		if ev.live {
			if len(j.current.Nested) != 0 {
				end.Duration = j.current.nestedDuration()
			} else {
				end.Duration = j.now().Sub(j.current.Start.Timestamp)
			}
		}
		if j.current.End != nil {
			if !ev.live || j.current.End.live {
				//!!! duplicate end event
			}
			//!!! compare events
		} else {
			j.current.End = ev
		}
		j.current = j.current.Parent

		//!!!
		/*
			if j.position.End == nil {
				// Nothing to do, end event for the current position.
			} else {
				// The current position is already ended,
				// this must be end event for the parent span.
				if j.position != j.position.Parent.Nested[len(j.position.Parent.Nested)-1] {
					panic("inconsistent")
				}
				j.position = j.position.Parent
			}
		*/
	}
	if span.Parent != nil {
		ev.Nesting = span.Parent.Start.Nesting + 1
	}
	//!!!
	/*
		if j.Span == nil {
			if start == nil {
				return false, nil, fmt.Errorf("the initial journal event is not start")
			}
			j.Span = &Span{
				Start: ev,
			}
			return true, j.Span, nil
		}
		last := j.lastOpen()
		if last == nil {
			return false, nil, fmt.Errorf("no open spans to append")
		}
		if start != nil {
			span := &Span{
				Start: ev,
			}
			last.Nested = append(last.Nested, span)
			return true, span, nil
		}
		if end == nil {
			return false, nil, fmt.Errorf("bad event type")
		}
		if ev.live {
			if len(last.Nested) != 0 {
				end.Duration = last.nestedDuration()
			} else {
				end.Duration = j.now().Sub(last.Start.Timestamp)
			}
		}
		last.End = ev
	*/
	return true, span, nil
}

func (j *Journal) closeAllOpen() error {
	for j.current != nil {
		outerEnd := SpanEnd{
			Error:       "nested error",
			NestedError: true,
		}
		var err error
		switch {
		case j.current.Start.FlowStart != nil:
			_, err = j.Append(&EventFlowEnd{SpanEnd: outerEnd})
		case j.current.Start.AgentStart != nil:
			_, err = j.Append(&EventAgentEnd{SpanEnd: outerEnd})
		case j.current.Start.LLMResponse != nil:
			_, err = j.Append(&EventLLMResponse{SpanEnd: outerEnd})
		case j.current.Start.ToolResult != nil:
			_, err = j.Append(&EventToolResult{SpanEnd: outerEnd})
		default:
			panic("bad start event type")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Span) nestedDuration() time.Duration {
	var duration time.Duration
	for _, n := range s.Nested {
		_, end := n.End.startEnd()
		duration += end.Duration
	}
	return duration
}

func (ev *Event) startEnd() (*SpanStart, *SpanEnd) {
	switch {
	case ev.FlowStart != nil:
		return &ev.FlowStart.SpanStart, nil
	case ev.FlowEnd != nil:
		return nil, &ev.FlowEnd.SpanEnd
	case ev.ActionStart != nil:
		return &ev.ActionStart.SpanStart, nil
	case ev.ActionEnd != nil:
		return nil, &ev.ActionEnd.SpanEnd
	case ev.AgentStart != nil:
		return &ev.AgentStart.SpanStart, nil
	case ev.AgentEnd != nil:
		return nil, &ev.AgentEnd.SpanEnd
	case ev.LLMRequest != nil:
		return &ev.LLMRequest.SpanStart, nil
	case ev.LLMResponse != nil:
		return nil, &ev.LLMResponse.SpanEnd
	case ev.ToolCall != nil:
		return &ev.ToolCall.SpanStart, nil
	case ev.ToolResult != nil:
		return nil, &ev.ToolResult.SpanEnd
	}
	return nil, nil
}

func (ev *Event) Description() string {
	switch {
	case ev.FlowStart != nil:
		return fmt.Sprintf("starting flow %v...", ev.FlowStart.Name)
	case ev.FlowEnd != nil:
		return fmt.Sprintf("finished flow")
	case ev.ActionStart != nil:
		return fmt.Sprintf("starting action %v...", ev.ActionStart.Name)
	case ev.ActionEnd != nil:
		return fmt.Sprintf("finished action")
	case ev.AgentStart != nil:
		return fmt.Sprintf("starting agent %v...", ev.AgentStart.Name)
	case ev.AgentEnd != nil:
		return fmt.Sprintf("finished agent")
	case ev.LLMRequest != nil:
		return fmt.Sprintf("starting LLM request...")
	case ev.LLMResponse != nil:
		return fmt.Sprintf("finished LLM request")
	case ev.ToolCall != nil:
		return fmt.Sprintf("starting tool call %v...", ev.ToolCall.Name)
	case ev.ToolResult != nil:
		return fmt.Sprintf("finished tool call")
	}
	return fmt.Sprintf("UNHANDLED EVENT %+v", *ev)
}
