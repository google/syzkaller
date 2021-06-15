// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
)

const (
	tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
	// Used in the config map as a prefix to distinguish auth identifiers from secret passwords
	// (which contain arbitrary strings, that can't have this prefix).
	oauthMagic = "OauthSubject:"
)

type jwtClaims struct {
	subject    string  `json:sub`
	expiration float64 `json:exp`
	audience   string  `json:aud`
}

func queryTokenInfo(tokenValue string) (*jwtClaims, error) {
	resp, err := http.PostForm(tokenInfoEndpoint, url.Values{"id_token": {tokenValue}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	claims := new(jwtClaims)
	if err = json.Unmarshal(body, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Returns the verified subject value based on the provided header
// value or "" if it can't be determined. A valid result starts with
// oauthMagic.
func determineAuthSubj(c context.Context, authHeader []string) string {
	if len(authHeader) != 1 || !strings.HasPrefix("Bearer", authHeader[0]) {
		// This is a normal case when the client uses a password.
		return ""
	}
	// Values past this point are real authentication attempts. Whether
	// or not they are valid is the question.
	tokenValue := strings.TrimSpace(strings.TrimPrefix(authHeader[0], "Bearer"))
	claims, err := queryTokenInfo(tokenValue)
	if err != nil {
		log.Errorf(c, "Failed token validation %v", err)
		return ""
	}
	if claims.audience != dashapi.DashboardAudience {
		log.Errorf(c, "Unexpected audience %v", claims.audience)
		return ""
	}
	if claims.expiration < float64(time.Now().Unix()) {
		log.Errorf(c, "Token past expiration %v", claims.expiration)
		return ""
	}
	return oauthMagic + claims.subject
}

// Verifies that the given credentials are acceptable and returns the
// corresponding namespace.
func checkClient(name0, secretPassword, oauthSubject string) (string, error) {
	checkAuth := func(ns, a string) (string, error) {
		if strings.HasPrefix(oauthMagic, a) && a == oauthSubject {
			return ns, nil
		}
		if a != secretPassword {
			return ns, ErrAccess
		}
		return ns, nil
	}
	for name, authenticator := range config.Clients {
		if name == name0 {
			return checkAuth("", authenticator)
		}
	}
	for ns, cfg := range config.Namespaces {
		for name, authenticator := range cfg.Clients {
			if name == name0 {
				return checkAuth(ns, authenticator)
			}
		}
	}
	return "", ErrAccess
}
