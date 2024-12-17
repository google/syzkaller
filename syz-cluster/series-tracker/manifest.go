// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type InboxInfo struct {
	Prefix string
	Epochs int
}

func (ii InboxInfo) EpochURL(id int) string {
	return fmt.Sprintf("%s/git/%d.git", ii.Prefix, id)
}

func (ii InboxInfo) LastEpochURL() string {
	return ii.EpochURL(ii.Epochs - 1)
}

var archiveRe = regexp.MustCompile(`/([\w-]+)/git/(\d+)\.git`)

func ParseManifest(baseURL string, jsonData []byte) (map[string]*InboxInfo, error) {
	var rawMap map[string]json.RawMessage
	err := json.Unmarshal(jsonData, &rawMap)
	if err != nil {
		return nil, err
	}
	ret := map[string]*InboxInfo{}
	for url := range rawMap {
		groups := archiveRe.FindStringSubmatch(url)
		if len(groups) == 0 {
			// TODO: monitor these.
			log.Printf("unexpected manifest.js key: %q", url)
			continue
		}
		epoch, err := strconv.Atoi(groups[2])
		if err != nil {
			log.Printf("invalid manifest.js key: %q", url)
			continue
		}
		inbox := ret[groups[1]]
		if inbox == nil {
			inbox = &InboxInfo{Prefix: fmt.Sprintf("%s/%s", baseURL, groups[1])}
			ret[groups[1]] = inbox
		}
		inbox.Epochs = max(inbox.Epochs, epoch+1)
	}
	return ret, nil
}

func QueryManifest(baseURL string) (map[string]*InboxInfo, error) {
	resp, err := http.Get(baseURL + "/manifest.js.gz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gzReader)
	if err != nil {
		return nil, err
	}
	return ParseManifest(baseURL, buf.Bytes())
}

// ManifestSource keeps an up to date version of the manifest.
type ManifestSource struct {
	mu          sync.Mutex
	url         string
	latestOk    map[string]*InboxInfo
	firstLoaded chan struct{} // The channel will be closed on the first successful load.
}

func NewManifestSource(baseURL string) *ManifestSource {
	return &ManifestSource{
		url:         baseURL,
		firstLoaded: make(chan struct{}),
	}
}

func (ms *ManifestSource) Loop(ctx context.Context) {
	// When we try to load for the first time, retry more frequently.
	const backOffPeriod = time.Minute * 15
	// Then, update rarely. New epochs are very infrequent.
	const refreshPeriod = time.Hour * 12

	alreadyLoaded := false
	nextAttemptIn := backOffPeriod
	for {
		info, err := QueryManifest(ms.url)
		log.Printf("loaded manifest: %v", err)
		if err == nil {
			ms.mu.Lock()
			ms.latestOk = info
			ms.mu.Unlock()
			if !alreadyLoaded {
				alreadyLoaded = true
				nextAttemptIn = refreshPeriod
				close(ms.firstLoaded)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextAttemptIn):
			break
		}
	}

}

func (ms *ManifestSource) Get(ctx context.Context) map[string]*InboxInfo {
	select {
	case <-ms.firstLoaded:
		ms.mu.Lock()
		defer ms.mu.Unlock()
		return ms.latestOk
	case <-ctx.Done():
		return nil
	}
}
