// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type FuncProxyURI func(filePath, commit string) string

type webGit struct {
	funcProxy FuncProxyURI
}

func (mr *webGit) GetFileVersions(targetFilePath string, repoCommits ...RepoCommit,
) (FileVersions, error) {
	res := make(FileVersions)
	for _, repoCommit := range repoCommits {
		fileBytes, err := mr.loadFile(targetFilePath, repoCommit.Repo, repoCommit.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err == errFileNotFound {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to loadFile: %w", err)
		}
		res[repoCommit] = string(fileBytes)
	}
	return res, nil
}

var errFileNotFound = errors.New("file not found")

func (mr *webGit) loadFile(filePath, repo, commit string) ([]byte, error) {
	var uri string
	if mr.funcProxy != nil {
		uri = mr.funcProxy(filePath, commit)
	} else {
		uri = fmt.Sprintf("%s/plain/%s", repo, filePath)
		if commit != "latest" {
			uri += "?id=" + commit
		}
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %v: %w", uri, err)
	}
	u.Scheme = "https"
	uri = u.String()
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to http.Get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, errFileNotFound
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error: status %d getting '%s'", resp.StatusCode, uri)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to io.ReadAll from body: %w", err)
	}
	if isGerritServer(resp) {
		if body, err = base64.StdEncoding.DecodeString(string(body)); err != nil {
			return nil, fmt.Errorf("base64.StdEncoding.DecodeString: %w", err)
		}
	}
	return body, nil
}

func isGerritServer(resp *http.Response) bool {
	for _, headerVals := range resp.Header {
		for _, header := range headerVals {
			if strings.Contains(header, "gerrit") {
				return true
			}
		}
	}
	return false
}

func MakeWebGit(funcProxy FuncProxyURI) FileVersProvider {
	return &webGit{
		funcProxy: funcProxy,
	}
}
