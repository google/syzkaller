// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	csrfFormField    = "csrf-token"
	csrfTokenTTL     = 24 * time.Hour
	csrfClockSkew    = 5 * time.Minute
	csrfMinSecretLen = 32
)

var crossOriginProtection = http.NewCrossOriginProtection()

// handleCSRF allows only GET, HEAD and POST. POST requests must come from a signed-in
// user with at least AccessUser, pass the Fetch Metadata / Origin checks and carry
// a valid CSRF token in the body. GET and HEAD pass through unchecked, so handlers
// must read state-changing inputs only via r.PostFormValue.
func handleCSRF(fn contextHandler) contextHandler {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return fn(ctx, w, r)
		case http.MethodPost:
		default:
			return ErrClientMethodNotAllowed
		}
		if err := checkAccessLevel(ctx, r, AccessUser); err != nil {
			return err
		}
		if err := crossOriginProtection.Check(r); err != nil {
			return fmt.Errorf("%w: %w", ErrClientForbidden, err)
		}
		if err := checkCSRFToken(ctx, r.PostFormValue(csrfFormField)); err != nil {
			return err
		}
		return fn(ctx, w, r)
	}
}

func generateCSRFToken(ctx context.Context) string {
	email := csrfUserEmail(ctx)
	if email == "" {
		return ""
	}
	ts := strconv.FormatInt(timeNow(ctx).Unix(), 10)
	mac := computeCSRFMAC([]byte(getConfig(ctx).CSRFSecret), email, ts)
	return ts + ":" + base64.RawURLEncoding.EncodeToString(mac)
}

func checkCSRFToken(ctx context.Context, token string) error {
	email := csrfUserEmail(ctx)
	if email == "" {
		return ErrAccess
	}
	tsStr, sigStr, ok := strings.Cut(token, ":")
	if !ok {
		return fmt.Errorf("%w: missing or malformed CSRF token", ErrClientForbidden)
	}
	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid CSRF token timestamp", ErrClientForbidden)
	}
	now := timeNow(ctx)
	issuedAt := time.Unix(tsUnix, 0)
	if issuedAt.After(now.Add(csrfClockSkew)) || now.Sub(issuedAt) > csrfTokenTTL {
		return fmt.Errorf("%w: expired CSRF token", ErrClientForbidden)
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return fmt.Errorf("%w: invalid CSRF token signature", ErrClientForbidden)
	}
	secret := getConfig(ctx).CSRFSecret
	if secret == "" {
		return fmt.Errorf("CSRFSecret is not configured")
	}
	wantMAC := computeCSRFMAC([]byte(secret), email, tsStr)
	if !hmac.Equal(gotMAC, wantMAC) {
		return fmt.Errorf("%w: invalid CSRF token", ErrClientForbidden)
	}
	return nil
}

func csrfUserEmail(ctx context.Context) string {
	u := currentUser(ctx)
	if u == nil || u.Email == "" {
		return ""
	}
	if _, al := userAccessLevel(u, "", getConfig(ctx)); al < AccessUser {
		return ""
	}
	return u.Email
}

func computeCSRFMAC(secret []byte, email, ts string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(email))
	mac.Write([]byte(":"))
	mac.Write([]byte(ts))
	return mac.Sum(nil)
}
