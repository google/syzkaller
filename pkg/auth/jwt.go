// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	DashboardAudience = "https://syzkaller.appspot.com/api"
)

type ExpiringToken struct {
	Token      string
	Expiration time.Time
}

// Returns the unverified expiration value from the given JWT token.
func extractJwtExpiration(token string) (time.Time, error) {
	// https://datatracker.ietf.org/doc/html/rfc7519#section-3
	pieces := strings.Split(token, ".")
	if len(pieces) != 3 {
		return time.Time{}, fmt.Errorf("unexpected number of JWT components %v", len(pieces))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(pieces[1])
	if err != nil {
		return time.Time{}, err
	}
	claims := struct {
		Expiration int64 `json:"exp"`
	}{-123456} // Hopefully a notably broken value.
	if err = json.Unmarshal(decoded, &claims); err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.Expiration, 0), nil
}

// Queries the metadata server and returns the bearer token of the
// service account. The token is scoped for the official dashboard.
// The types of ctor and doer are the same as in http.NewRequest and
// http.DefaultClient.Do.
func RetrieveJwtToken(ctor func(method, url string, body io.Reader) (*http.Request, error),
	doer func(req *http.Request) (*http.Response, error)) (*ExpiringToken, error) {
	const v1meta = "http://metadata.google.internal/computeMetadata/v1"
	req, err := ctor("GET", v1meta+"/instance/service-accounts/default/identity?audience="+DashboardAudience, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := doer(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	token := string(data)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed metadata get %v: %s", resp.Status, token)
	}
	expiration, err := extractJwtExpiration(token)
	if err != nil {
		return nil, err
	}
	return &ExpiringToken{token, expiration}, nil
}
