// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DashboardAudience = "https://syzkaller.appspot.com/api"
)

type expiringToken struct {
	value      string
	expiration time.Time
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

type (
	// The types of ctor and doer are the same as in http.NewRequest and
	// http.DefaultClient.Do.
	requestCtor func(method, url string, body io.Reader) (*http.Request, error)
	requestDoer func(req *http.Request) (*http.Response, error)
)

// Queries the metadata server and returns the bearer token of the
// service account. The token is scoped for the official dashboard.
func retrieveJwtToken(ctor requestCtor, doer requestDoer) (*expiringToken, error) {
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
	data, err := io.ReadAll(resp.Body)
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
	return &expiringToken{token, expiration}, nil
}

// TokenCache keeps the tokens for reuse by Get.
type TokenCache struct {
	lock  sync.Mutex
	token *expiringToken
	ctor  requestCtor
	doer  requestDoer
}

// MakeCache creates a new cache or returns an error if tokens aren't
// available.
func MakeCache(ctor func(method, url string, body io.Reader) (*http.Request, error),
	doer func(req *http.Request) (*http.Response, error)) (*TokenCache, error) {
	token, err := retrieveJwtToken(ctor, doer)
	if err != nil {
		return nil, err
	}
	return &TokenCache{sync.Mutex{}, token, ctor, doer}, nil
}

// Get returns a potentially cached value of the token or renews as
// necessary. The now parameter provides the current time for cache
// expiration. The returned value is suitable for Authorization header
// and syz-hub Key requests.
func (cache *TokenCache) Get(now time.Time) (string, error) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	// A typical token returned by metadata server is valid for an hour.
	// Refreshing a minute early should give the recipient plenty of time
	// to verify the token.
	if cache.token.expiration.Sub(now) < time.Minute {
		// Keeping the lock while making http request is dubious, but
		// making multiple concurrent requests is not any better.
		t, err := retrieveJwtToken(cache.ctor, cache.doer)
		if err != nil {
			// Can't get a new token, so returning the error preemptively.
			return "", err
		}
		cache.token = t
	}
	return "Bearer " + cache.token.value, nil
}
