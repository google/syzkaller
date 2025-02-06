// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	res, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to http.Get: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == 404 {
		return nil, errFileNotFound
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("error: status %d getting '%s'", res.StatusCode, uri)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to io.ReadAll from body: %w", err)
	}
	return body, nil
}

func MakeWebGit(funcProxy FuncProxyURI) FileVersProvider {
	return &webGit{
		funcProxy: funcProxy,
	}
}
