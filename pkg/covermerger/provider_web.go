// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v2"
)

type FuncProxyURI func(filePath, commit string) string

type webGit struct {
	funcProxy FuncProxyURI
}

func (mr *webGit) GetFileVersions(ctx context.Context, targetFilePath string, repoCommits ...RepoCommit,
) (FileVersions, error) {
	res := make(FileVersions)
	for _, repoCommit := range repoCommits {
		fileBytes, err := mr.loadFile(ctx, targetFilePath, repoCommit.Repo, repoCommit.Commit)
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

func (mr *webGit) loadFile(ctx context.Context, filePath, repo, commit string) ([]byte, error) {
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
		return nil, fmt.Errorf("url.Parse(%v): %w", uri, err)
	}
	u.Scheme = "https"
	uri = u.String()
	res, err := httpAuthGet(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("httpAuthGet: %w", err)
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
		return nil, fmt.Errorf("io.ReadAll(res.Body): %w", err)
	}
	return body, nil
}

func MakeWebGit(funcProxy FuncProxyURI) FileVersProvider {
	return &webGit{
		funcProxy: funcProxy,
	}
}

func httpAuthGet(ctx context.Context, url string) (resp *http.Response, err error) {
	tokenSource, err := google.DefaultTokenSource(ctx, iam.CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("google.DefaultTokenSource: %w", err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("tokenSource.Token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	return http.DefaultClient.Do(req)
}
