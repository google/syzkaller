// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzspec provides utilities and actions for parsing and analyzing syzlang descriptions.
package syzspec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
)

const minBlobLen = 128

var (
	StringLiteralSeq = regexp.MustCompile(`"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*`)
	placeholderRegex = regexp.MustCompile(`"\$BLOB_[a-f0-9]{12}"`)
)

// BlobStore manages the mapping between large data blobs and their placeholders.
type BlobStore struct {
	mu                sync.RWMutex
	placeholderToBlob map[string]string
}

// RegisterBlob registers a data blob string and returns its placeholder.
func (s *BlobStore) RegisterBlob(blob string) string {
	h := sha256.Sum256([]byte(blob))
	hashStr := hex.EncodeToString(h[:6]) // Use 12 hex characters.
	ph := fmt.Sprintf("\"$BLOB_%s\"", hashStr)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.placeholderToBlob == nil {
		s.placeholderToBlob = make(map[string]string)
	}
	s.placeholderToBlob[ph] = blob
	return ph
}

// ReplaceBlobs replaces all large string literal blobs in the content with their placeholders.
func (s *BlobStore) ReplaceBlobs(content string) string {
	return StringLiteralSeq.ReplaceAllStringFunc(content, func(match string) string {
		if len(match) >= minBlobLen {
			return s.RegisterBlob(match)
		}
		return match
	})
}

// RestoreBlobs restores all placeholders in the content back to their original blobs.
func (s *BlobStore) RestoreBlobs(content string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.placeholderToBlob) == 0 {
		return content
	}
	return placeholderRegex.ReplaceAllStringFunc(content, func(match string) string {
		if blob, ok := s.placeholderToBlob[match]; ok {
			return blob
		}
		return match
	})
}
