// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package orcarouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
)

// AuthError means the credential itself was rejected. Retrying cannot help;
// the caller must replace the API key.
type AuthError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("orcarouter: authentication failed (status %d%s)", e.StatusCode, codeSuffix(e.Code))
}

// AccessError means the key is valid but is not allowed to use the requested
// model or operation. Retrying cannot help.
type AccessError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *AccessError) Error() string {
	return fmt.Sprintf("orcarouter: request is not permitted (status %d%s)", e.StatusCode, codeSuffix(e.Code))
}

func codeSuffix(code string) string {
	if code == "" {
		return ""
	}
	return ", " + code
}

type apiError struct {
	Error *struct {
		Message string          `json:"message"`
		Type    string          `json:"type"`
		Code    json.RawMessage `json:"code"`
	} `json:"error"`
}

func (e *apiError) message() string {
	if e == nil || e.Error == nil {
		return ""
	}
	return e.Error.Message
}

func (e *apiError) code() string {
	if e == nil || e.Error == nil || len(e.Error.Code) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(e.Error.Code, &text); err == nil {
		return text
	}
	return strings.Trim(string(e.Error.Code), `"`)
}

func parseAPIError(body []byte) *apiError {
	var parsed apiError
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	if parsed.Error == nil {
		return nil
	}
	return &parsed
}

// httpStatusError maps a non-2xx inference or discovery response to the
// backend's error taxonomy. Response bodies are bounded and never contain
// request headers, so an API key cannot leak through an error.
func httpStatusError(status int, fallback string, body []byte) error {
	apiErr := parseAPIError(body)
	message := apiErr.message()
	if message == "" {
		message = fallback
	}
	code := apiErr.code()
	message = truncate(message, 500)
	switch status {
	case http.StatusUnauthorized:
		return &AuthError{StatusCode: status, Code: code, Message: message}
	case http.StatusForbidden:
		return &AccessError{StatusCode: status, Code: code, Message: message}
	case http.StatusTooManyRequests:
		return &backend.RetryError{
			Delay: 30 * time.Second, IsExponential: true,
			Err: fmt.Errorf("orcarouter: rate limited: %s", message),
		}
	case http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &backend.RetryError{
			Delay: time.Second, IsExponential: true,
			Err: fmt.Errorf("orcarouter: temporary failure (status %d): %s", status, message),
		}
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		if isTokenOverflow(message) {
			return &backend.InputTokenOverflowError{
				Err: fmt.Errorf("orcarouter: input exceeds the model limit: %s", message),
			}
		}
		return fmt.Errorf("orcarouter: request failed (status %d): %s", status, message)
	default:
		return fmt.Errorf("orcarouter: request failed (status %d): %s", status, message)
	}
}

func isTokenOverflow(message string) bool {
	low := strings.ToLower(message)
	for _, marker := range []string{
		"context length", "context_length", "maximum context", "input token",
		"too many tokens", "prompt is too long", "token limit",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// retryAfterDelay reads a Retry-After header (seconds or HTTP date).
func retryAfterDelay(resp *http.Response) time.Duration {
	value := resp.Header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if delay := time.Until(when); delay > 0 {
			return delay
		}
	}
	return 0
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}
