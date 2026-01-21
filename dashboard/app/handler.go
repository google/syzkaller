// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/html"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/user"
)

// This file contains common middleware for UI handlers (auth, html templates, etc).

type contextHandler func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

func handlerWrapper(fn contextHandler) http.Handler {
	return handleContext(handleAuth(fn))
}

func handleContext(fn contextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), &currentURLKey, r.URL.RequestURI())
		authorizedUser, _ := userAccessLevel(currentUser(ctx), "", getConfig(ctx))
		if !authorizedUser {
			if !throttleRequest(ctx, w, r) {
				return
			}
			defer backpressureRobots(ctx, r)()
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		gzw := newGzipResponseWriterCloser(w)
		defer gzw.Close()
		err := fn(ctx, gzw, r)
		if err == nil {
			if err = gzw.writeResult(r); err == nil {
				return
			}
		}
		hdr := commonHeaderRaw(ctx, r)
		data := &struct {
			Header  *uiHeader
			Error   string
			TraceID string
		}{
			Header:  hdr,
			Error:   err.Error(),
			TraceID: strings.Join(r.Header["X-Cloud-Trace-Context"], " "),
		}
		if err == ErrAccess {
			if hdr.LoginLink != "" {
				http.Redirect(w, r, hdr.LoginLink, http.StatusTemporaryRedirect)
				return
			}
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		var redir *ErrRedirect
		if errors.As(err, &redir) {
			http.Redirect(w, r, redir.Error(), http.StatusFound)
			return
		}

		status := logErrorPrepareStatus(ctx, err)
		w.WriteHeader(status)
		if err1 := templates.ExecuteTemplate(w, "error.html", data); err1 != nil {
			combinedError := fmt.Sprintf("got err \"%v\" processing ExecuteTemplate() for err \"%v\"", err1, err)
			http.Error(w, combinedError, http.StatusInternalServerError)
		}
	})
}

func logErrorPrepareStatus(ctx context.Context, err error) int {
	status := http.StatusInternalServerError
	logf := log.Errorf
	var clientError *ErrClient
	if errors.As(err, &clientError) {
		// We don't log these as errors because they can be provoked
		// by invalid user requests, so we don't wan't to pollute error log.
		logf = log.Warningf
		status = clientError.HTTPStatus()
	}
	logf(ctx, "appengine error: %v", err)
	return status
}

func isRobot(r *http.Request) bool {
	userAgent := strings.ToLower(strings.Join(r.Header["User-Agent"], " "))
	if strings.HasPrefix(userAgent, "curl") ||
		strings.HasPrefix(userAgent, "wget") {
		return true
	}
	return false
}

// We don't count the request round trip time here.
// Actual delay will be the minDelay + requestRoundTripTime.
func backpressureRobots(ctx context.Context, r *http.Request) func() {
	if !isRobot(r) {
		return func() {}
	}
	cfg := getConfig(ctx).Throttle
	if cfg.Empty() {
		return func() {}
	}
	minDelay := cfg.Window / time.Duration(cfg.Limit)
	delayUntil := time.Now().Add(minDelay)
	return func() {
		select {
		case <-ctx.Done():
		case <-time.After(time.Until(delayUntil)):
		}
	}
}

func throttleRequest(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	// AppEngine removes all App Engine-specific headers, which include
	// X-Appengine-User-IP and X-Forwarded-For.
	// https://cloud.google.com/appengine/docs/standard/reference/request-headers?tab=python#removed_headers
	ip := r.Header.Get("X-Appengine-User-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		ip, _, _ = strings.Cut(ip, ",") // X-Forwarded-For is a comma-delimited list.
		ip = strings.TrimSpace(ip)
	}
	cron := r.Header.Get("X-Appengine-Cron") != ""
	if ip == "" || cron {
		log.Infof(ctx, "cannot throttle request from %q, cron %t", ip, cron)
		return true
	}
	accept, err := ThrottleRequest(ctx, ip)
	if errors.Is(err, ErrThrottleTooManyRetries) {
		// We get these at peak QPS anyway, it's not an error.
		log.Warningf(ctx, "failed to throttle: %v", err)
	} else if err != nil {
		log.Errorf(ctx, "failed to throttle: %v", err)
	}
	log.Infof(ctx, "throttling for %q: %t", ip, accept)
	if !accept {
		http.Error(w, throttlingErrorMessage(ctx), http.StatusTooManyRequests)
		return false
	}
	return true
}

func throttlingErrorMessage(ctx context.Context) string {
	ret := fmt.Sprintf("429 Too Many Requests\nAllowed rate is %d requests per %d seconds.",
		getConfig(ctx).Throttle.Limit, int(getConfig(ctx).Throttle.Window.Seconds()))
	email := getConfig(ctx).ContactEmail
	if email == "" {
		return ret
	}
	return fmt.Sprintf("%s\nPlease contact us at %s if you need access to our data.", ret, email)
}

var currentURLKey = "the URL of the HTTP request in context"

func getCurrentURL(ctx context.Context) string {
	val, ok := ctx.Value(&currentURLKey).(string)
	if ok {
		return val
	}
	return ""
}

type (
	ErrClient   struct{ error }
	ErrRedirect struct{ error }
)

var ErrClientNotFound = &ErrClient{errors.New("resource not found")}
var ErrClientBadRequest = &ErrClient{errors.New("bad request")}

func (ce *ErrClient) HTTPStatus() int {
	switch ce {
	case ErrClientNotFound:
		return http.StatusNotFound
	case ErrClientBadRequest:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func handleAuth(fn contextHandler) contextHandler {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := checkAccessLevel(ctx, r, getConfig(ctx).AccessLevel); err != nil {
			return err
		}
		return fn(ctx, w, r)
	}
}

func serveTemplate(w http.ResponseWriter, name string, data any) error {
	buf := new(bytes.Buffer)
	if err := templates.ExecuteTemplate(buf, name, data); err != nil {
		return err
	}
	w.Write(buf.Bytes())
	return nil
}

type uiHeader struct {
	Admin               bool
	AI                  bool // Enable UI elements related to AI
	URLPath             string
	LoginLink           string
	AnalyticsTrackingID string
	Subpage             string
	Namespace           string
	ContactEmail        string
	BugCounts           *CachedBugStats
	MissingBackports    int
	Namespaces          []uiNamespace
	ShowSubsystems      bool
	ShowCoverageMenu    bool
	Message             string // Show message box with this message when the page loads.
}

type uiNamespace struct {
	Name    string
	Caption string
}

type cookieData struct {
	Namespace string `json:"namespace"`
}

func commonHeaderRaw(ctx context.Context, r *http.Request) *uiHeader {
	h := &uiHeader{
		Admin:               accessLevel(ctx, r) == AccessAdmin,
		URLPath:             r.URL.Path,
		AnalyticsTrackingID: getConfig(ctx).AnalyticsTrackingID,
		ContactEmail:        getConfig(ctx).ContactEmail,
	}
	if user.Current(ctx) == nil {
		h.LoginLink, _ = user.LoginURL(ctx, r.URL.String())
	}
	return h
}

func commonHeader(ctx context.Context, r *http.Request, w http.ResponseWriter, ns string) (*uiHeader, error) {
	accessLevel := accessLevel(ctx, r)
	if ns == "" {
		ns = strings.ToLower(r.URL.Path)
		if ns != "" && ns[0] == '/' {
			ns = ns[1:]
		}
		if pos := strings.IndexByte(ns, '/'); pos != -1 {
			ns = ns[:pos]
		}
	}
	h := commonHeaderRaw(ctx, r)
	const adminPage = "admin"
	isAdminPage := r.URL.Path == "/"+adminPage
	found := false
	for ns1, cfg := range getConfig(ctx).Namespaces {
		if accessLevel < cfg.AccessLevel {
			if ns1 == ns {
				return nil, ErrAccess
			}
			continue
		}
		if ns1 == ns {
			found = true
		}
		if getNsConfig(ctx, ns1).Decommissioned {
			continue
		}
		h.Namespaces = append(h.Namespaces, uiNamespace{
			Name:    ns1,
			Caption: cfg.DisplayTitle,
		})
	}
	sort.Slice(h.Namespaces, func(i, j int) bool {
		return h.Namespaces[i].Caption < h.Namespaces[j].Caption
	})
	cookie := decodeCookie(r)
	if !found {
		ns = getConfig(ctx).DefaultNamespace
		if cfg := getNsConfig(ctx, cookie.Namespace); cfg != nil && cfg.AccessLevel <= accessLevel {
			ns = cookie.Namespace
		}
		if accessLevel == AccessAdmin {
			ns = adminPage
		}
		if ns != adminPage || !isAdminPage {
			return nil, &ErrRedirect{fmt.Errorf("/%v", ns)}
		}
	}
	if ns != adminPage {
		cfg := getNsConfig(ctx, ns)
		h.Namespace = ns
		h.AI = cfg.AI && accessLevel >= AIAccessLevel
		h.ShowSubsystems = cfg.Subsystems.Service != nil
		cookie.Namespace = ns
		encodeCookie(w, cookie)
		cached, err := CacheGet(ctx, r, ns)
		if err != nil {
			return nil, err
		}
		h.BugCounts = &cached.Total
		h.MissingBackports = cached.MissingBackports
		h.ShowCoverageMenu = cfg.Coverage != nil
	}
	return h, nil
}

const cookieName = "syzkaller"

func decodeCookie(r *http.Request) *cookieData {
	cd := new(cookieData)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return cd
	}
	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return cd
	}
	json.Unmarshal(decoded, cd)
	return cd
}

func encodeCookie(w http.ResponseWriter, cd *cookieData) {
	data, err := json.Marshal(cd)
	if err != nil {
		return
	}
	cookie := &http.Cookie{
		Name:    cookieName,
		Value:   base64.StdEncoding.EncodeToString(data),
		Expires: time.Now().Add(time.Hour * 24 * 365),
	}
	http.SetCookie(w, cookie)
}

var templates = html.CreateGlob("*.html")

// gzipResponseWriterCloser accumulates the gzipped result.
// In case of error during the handler processing, we'll drop this gzipped data.
// It allows to call http.Error in the middle of the response generation.
//
// For 200 Ok responses we return the compressed data or decompress it depending on the client Accept-Encoding header.
type gzipResponseWriterCloser struct {
	w                 *gzip.Writer
	plainResponseSize int
	buf               *bytes.Buffer
	rw                http.ResponseWriter
}

func (g *gzipResponseWriterCloser) Write(p []byte) (n int, err error) {
	g.plainResponseSize += len(p)
	return g.w.Write(p)
}

func (g *gzipResponseWriterCloser) Close() {
	if g.w != nil {
		g.w.Close()
	}
}

func (g *gzipResponseWriterCloser) Header() http.Header {
	return g.rw.Header()
}

func (g *gzipResponseWriterCloser) WriteHeader(statusCode int) {
	g.rw.WriteHeader(statusCode)
}

func (g *gzipResponseWriterCloser) writeResult(r *http.Request) error {
	g.w.Close()
	g.w = nil
	clientSupportsGzip := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	if clientSupportsGzip {
		g.rw.Header().Set("Content-Encoding", "gzip")
		_, err := g.rw.Write(g.buf.Bytes())
		return err
	}
	if g.plainResponseSize > 31<<20 { // 32MB is the AppEngine hard limit for the response size.
		return fmt.Errorf("len(response) > 31M, try to request gzipped: %w", ErrClientBadRequest)
	}
	gzr, err := gzip.NewReader(g.buf)
	if err != nil {
		return fmt.Errorf("gzip.NewReader: %w", err)
	}
	defer gzr.Close()
	_, err = io.Copy(g.rw, gzr)
	return err
}

func newGzipResponseWriterCloser(w http.ResponseWriter) *gzipResponseWriterCloser {
	buf := &bytes.Buffer{}
	return &gzipResponseWriterCloser{
		w:   gzip.NewWriter(buf),
		buf: buf,
		rw:  w,
	}
}
