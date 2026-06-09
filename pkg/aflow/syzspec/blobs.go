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
	blobMu            sync.RWMutex
	placeholderToBlob = make(map[string]string)
	blobToPlaceholder = make(map[string]string)
	StringLiteralSeq  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*`)
	placeholderRegex  = regexp.MustCompile(`"\$BLOB_[a-f0-9]{12}"`)
)

// RegisterBlob registers a data blob string and returns its placeholder.
func RegisterBlob(blob string) string {
	blobMu.Lock()
	defer blobMu.Unlock()
	if ph, ok := blobToPlaceholder[blob]; ok {
		return ph
	}
	// Calculate hash of the blob.
	h := sha256.Sum256([]byte(blob))
	hashStr := hex.EncodeToString(h[:6]) // Use 12 hex characters.
	ph := fmt.Sprintf("\"$BLOB_%s\"", hashStr)
	blobToPlaceholder[blob] = ph
	placeholderToBlob[ph] = blob
	return ph
}

// ReplaceBlobs replaces all large string literal blobs in the content with their placeholders.
func ReplaceBlobs(content string) string {
	return StringLiteralSeq.ReplaceAllStringFunc(content, func(match string) string {
		if len(match) >= minBlobLen {
			return RegisterBlob(match)
		}
		return match
	})
}

// RestoreBlobs restores all placeholders in the content back to their original blobs.
func RestoreBlobs(content string) string {
	blobMu.RLock()
	defer blobMu.RUnlock()
	return placeholderRegex.ReplaceAllStringFunc(content, func(match string) string {
		if blob, ok := placeholderToBlob[match]; ok {
			return blob
		}
		return match
	})
}
