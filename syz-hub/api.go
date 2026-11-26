// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/syz-hub/state"
)

const (
	maxCompressedBodySize = 64 << 20
	maxDecodedBodySize    = 256 << 20
	encodingGzip          = "gzip"
	errInternalServer     = "internal server error"
)

func (hub *Hub) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+hubapi.PathConnect, hub.httpConnect)
	mux.HandleFunc("POST "+hubapi.PathSync, hub.httpSync)
	return mux
}

func (hub *Hub) httpConnect(w http.ResponseWriter, r *http.Request) {
	name, ok := hub.authenticateRequest(w, r)
	if !ok {
		return
	}
	var req hubapi.ConnectReq
	if !decodeAPIRequest(w, r, &req) {
		return
	}
	if err := hub.connect(name, &req); err != nil {
		http.Error(w, errInternalServer, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (hub *Hub) httpSync(w http.ResponseWriter, r *http.Request) {
	name, ok := hub.authenticateRequest(w, r)
	if !ok {
		return
	}
	var req hubapi.SyncReq
	if !decodeAPIRequest(w, r, &req) {
		return
	}
	resp, err := hub.sync(name, &req)
	if err != nil {
		if errors.Is(err, state.ErrUnconnected) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, errInternalServer, http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, r, resp)
}

func (hub *Hub) authenticateRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	name, err := hub.checkManager(r.Header.Get(hubapi.HeaderClient), token, r.Header.Get(hubapi.HeaderManager))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return "", false
	}
	return name, true
}

func decodeAPIRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxCompressedBodySize)

	reader := io.Reader(r.Body)
	switch encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); encoding {
	case "":
	case encodingGzip:
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeBodyReadError(w, "invalid gzip body", err)
			return false
		}
		defer gz.Close()
		reader = gz
	default:
		http.Error(w, fmt.Sprintf("unsupported Content-Encoding %q", encoding), http.StatusUnsupportedMediaType)
		return false
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxDecodedBodySize+1))
	if err != nil {
		writeBodyReadError(w, "failed to read request body", err)
		return false
	}
	if len(data) > maxDecodedBodySize {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return false
	}
	if err := json.Unmarshal(data, dst); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
		return false
	}
	return true
}

func writeBodyReadError(w http.ResponseWriter, msg string, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, fmt.Sprintf("%s: %v", msg, err), http.StatusBadRequest)
}

func writeJSONResponse(w http.ResponseWriter, r *http.Request, resp any) {
	payload, err := json.Marshal(resp)
	if err != nil {
		log.Logf(0, "failed to marshal response: %v", err)
		http.Error(w, errInternalServer, http.StatusInternalServerError)
		return
	}
	w.Header().Add("Vary", "Accept-Encoding")
	if strings.Contains(r.Header.Get("Accept-Encoding"), encodingGzip) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(payload); err != nil {
			log.Logf(0, "failed to compress response: %v", err)
			http.Error(w, errInternalServer, http.StatusInternalServerError)
			return
		}
		if err := gz.Close(); err != nil {
			log.Logf(0, "failed to finalize compressed response: %v", err)
			http.Error(w, errInternalServer, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Encoding", encodingGzip)
		payload = buf.Bytes()
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(payload); err != nil && !errors.Is(err, context.Canceled) {
		log.Logf(0, "failed to write HTTP response: %v", err)
	}
}

func parseBearerToken(header string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}
