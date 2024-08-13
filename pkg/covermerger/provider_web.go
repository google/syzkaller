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

type webGit struct {
}

func (mr *webGit) GetFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (fileVersions, error) {
	res := make(fileVersions)
	for _, rbc := range rbcs {
		fileBytes, err := loadFile(targetFilePath, rbc.Repo, rbc.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err == errFileNotFound {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to loadFile: %w", err)
		}
		res[rbc] = string(fileBytes)
	}
	return res, nil
}

var errFileNotFound = errors.New("file not found")

func loadFile(filePath, repo, commit string) ([]byte, error) {
	uri := fmt.Sprintf("%s/plain/%s?id=%s", repo, filePath, commit)
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
		return nil, fmt.Errorf("error: status %d getting %s", res.StatusCode, uri)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to io.ReadAll from body: %w", err)
	}
	return body, nil
}

func MakeWebGit() FileVersProvider {
	return &webGit{}
}

func GetFileVersion(filePath, repo, commit string) (string, error) {
	rbc := RepoBranchCommit{repo, "", commit}
	files, err := MakeWebGit().GetFileVersions(nil,
		filePath,
		[]RepoBranchCommit{rbc})
	if err != nil {
		return "", fmt.Errorf("failed to GetFileVersions: %w", err)
	}
	return files[rbc], nil
}
