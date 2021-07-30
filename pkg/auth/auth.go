// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Relies on tokeninfo because it is properly documented:
// https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken

// The client
// The VM that wants to invoke the API:
// 1) Gets a token from the metainfo server with this http request:
//      META=http://metadata.google.internal/computeMetadata/v1
//      AUD=https://syzkaller.appspot.com/api
//      curl -sH 'Metadata-Flavor: Google' \
//           "$META/instance/service-accounts/default/identity?audience=$AUD"
// 2) Invokes /api with header 'Authorization: Bearer <token>'
//
// The AppEngine api server:
// 1) Receive the token, invokes this http request:
//      curl -s "https://oauth2.googleapis.com/tokeninfo?id_token=<token>"
// 2) Checks the resulting JSON having the expected audience and expiration.
// 3) Looks up the permissions in the config using the value of sub.
//
// https://cloud.google.com/iap/docs/signed-headers-howto#retrieving_the_user_identity
// from the IAP docs agrees to trust sub.

// Package auth contains authentication related code supporting secret
// passwords and oauth2 tokens on GCE.
package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// The official google oauth2 endpoint.
	GoogleTokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
	// Used in the config map as a prefix to distinguish auth identifiers from secret passwords
	// (which contain arbitrary strings, that can't have this prefix).
	OauthMagic = "OauthSubject:"
)

// Represent a verification backend.
type Endpoint struct {
	// URL supporting tokeninfo auth2 protocol.
	url string
	// TODO(blackgnezdo): cache tokens with a bit of care for concurrency.
}

func MakeEndpoint(u string) Endpoint {
	return Endpoint{url: u}
}

// The JSON representation of JWT claims.
type jwtClaimsParse struct {
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	// The field in the JSON is a string but contains a UNIX time.
	Expiration string `json:"exp"`
}

// The typed representation of JWT claims.
type jwtClaims struct {
	Subject  string
	Audience string
	// The app uses the typed value.
	Expiration time.Time
}

func (auth *Endpoint) queryTokenInfo(tokenValue string) (*jwtClaims, error) {
	resp, err := http.PostForm(auth.url, url.Values{"id_token": {tokenValue}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verification failed %v", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	claims := new(jwtClaimsParse)
	if err = json.Unmarshal(body, claims); err != nil {
		return nil, err
	}
	expInt, err := strconv.ParseInt(claims.Expiration, 10, 64)
	if err != nil {
		return nil, err
	}
	r := jwtClaims{
		Subject:    claims.Subject,
		Audience:   claims.Audience,
		Expiration: time.Unix(expInt, 0),
	}
	return &r, nil
}

// Returns the verified subject value based on the provided header
// value or "" if it can't be determined. A valid result starts with
// auth.OauthMagic. The now parameter is the current time to compare the
// claims against. The authHeader is styled as is typical for HTTP headers
// which carry the tokens prefixed by "Bearer " string.
func (auth *Endpoint) DetermineAuthSubj(now time.Time, authHeader []string) (string, error) {
	if len(authHeader) != 1 || !strings.HasPrefix(authHeader[0], "Bearer") {
		// This is a normal case when the client uses a password.
		return "", nil
	}
	// Values past this point are real authentication attempts. Whether
	// or not they are valid is the question.
	tokenValue := strings.TrimSpace(strings.TrimPrefix(authHeader[0], "Bearer"))
	claims, err := auth.queryTokenInfo(tokenValue)
	if err != nil {
		return "", err
	}
	if claims.Audience != DashboardAudience {
		err := fmt.Errorf("unexpected audience %v", claims.Audience)
		return "", err
	}
	if claims.Expiration.Before(now) {
		err := fmt.Errorf("token past expiration %v", claims.Expiration)
		return "", err
	}
	return OauthMagic + claims.Subject, nil
}
