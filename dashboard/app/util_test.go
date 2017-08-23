// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// The test uses aetest package that starts local dev_appserver and handles all requests locally:
// https://cloud.google.com/appengine/docs/standard/go/tools/localunittesting/reference
// The test requires installed appengine SDK (dev_appserver), so we guard it by aetest tag.
// Run the test with: goapp test -tags=aetest

// +build aetest

package dash

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	aemail "google.golang.org/appengine/mail"
	"google.golang.org/appengine/user"
)

type Ctx struct {
	t          *testing.T
	inst       aetest.Instance
	ctx        context.Context
	mockedTime time.Time
	emailSink  chan *aemail.Message
}

func NewCtx(t *testing.T) *Ctx {
	t.Parallel()
	inst, err := aetest.NewInstance(&aetest.Options{
		// Without this option datastore queries return data with slight delay,
		// which fails reporting tests.
		StronglyConsistentDatastore: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := inst.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &Ctx{
		t:          t,
		inst:       inst,
		ctx:        appengine.NewContext(r),
		mockedTime: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		emailSink:  make(chan *aemail.Message, 100),
	}
	registerContext(r, c)
	return c
}

func (c *Ctx) expectOK(err error) {
	if err != nil {
		c.t.Fatalf("\n%v: %v", caller(0), err)
	}
}

func (c *Ctx) expectFail(msg string, err error) {
	if err == nil {
		c.t.Fatal("\n%v: expected to fail, but it does not", caller(0))
	}
	if !strings.Contains(err.Error(), msg) {
		c.t.Fatalf("\n%v: expected to fail with %q, but failed with %q", caller(0), msg, err)
	}
}

func (c *Ctx) expectEQ(got, want interface{}) {
	if !reflect.DeepEqual(got, want) {
		c.t.Fatalf("\n%v: got %#v, want %#v", caller(0), got, want)
	}
}

func caller(skip int) string {
	_, file, line, _ := runtime.Caller(skip + 2)
	return fmt.Sprintf("%v:%v", filepath.Base(file), line)
}

func (c *Ctx) Close() {
	if !c.t.Failed() {
		// Ensure that we can render bugs in the final test state.
		c.expectOK(c.GET("/"))
		c.expectEQ(len(c.emailSink), 0)
	}
	unregisterContext(c)
	c.inst.Close()
}

func (c *Ctx) advanceTime(d time.Duration) {
	c.mockedTime = c.mockedTime.Add(d)
}

// API makes an api request to the app from the specified client.
func (c *Ctx) API(client, key, method string, req, reply interface{}) error {
	doer := func(r *http.Request) (*http.Response, error) {
		registerContext(r, c)
		w := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(w, r)
		// Later versions of Go have a nice w.Result method,
		// but we stuck on 1.6 on appengine.
		if w.Body == nil {
			w.Body = new(bytes.Buffer)
		}
		res := &http.Response{
			StatusCode: w.Code,
			Status:     http.StatusText(w.Code),
			Body:       ioutil.NopCloser(bytes.NewReader(w.Body.Bytes())),
		}
		return res, nil
	}

	c.t.Logf("API(%v): %#v", method, req)
	err := dashapi.Query(client, "", key, method, c.inst.NewRequest, doer, req, reply)
	if err != nil {
		c.t.Logf("ERROR: %v", err)
		return err
	}
	c.t.Logf("REPLY: %#v", reply)
	return nil
}

// GET sends authorized HTTP GET request to the app.
func (c *Ctx) GET(url string) error {
	return c.httpRequest("GET", url, "")
}

// POST sends authorized HTTP POST request to the app.
func (c *Ctx) POST(url, body string) error {
	return c.httpRequest("POST", url, body)
}

func (c *Ctx) httpRequest(method, url, body string) error {
	c.t.Logf("%v: %v", method, url)
	r, err := c.inst.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	registerContext(r, c)
	user := &user.User{
		Email:      "test@syzkaller.com",
		AuthDomain: "gmail.com",
		Admin:      true,
	}
	aetest.Login(user, r)
	w := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(w, r)
	c.t.Logf("REPLY: %v", w.Code)
	if w.Code != http.StatusOK {
		return fmt.Errorf("%v", w.Body.String())
	}
	return nil
}

func init() {
	// Mock time as some functionality relies on real time.
	timeNow = func(c context.Context) time.Time {
		return getRequestContext(c).mockedTime
	}
	sendEmail = func(c context.Context, msg *aemail.Message) error {
		getRequestContext(c).emailSink <- msg
		return nil
	}
}

// Machinery to associate mocked time with requests.
type RequestMapping struct {
	c   context.Context
	ctx *Ctx
}

var (
	requestMu       sync.Mutex
	requestContexts []RequestMapping
)

func registerContext(r *http.Request, c *Ctx) {
	requestMu.Lock()
	defer requestMu.Unlock()
	requestContexts = append(requestContexts, RequestMapping{appengine.NewContext(r), c})
}

func getRequestContext(c context.Context) *Ctx {
	requestMu.Lock()
	defer requestMu.Unlock()
	for _, m := range requestContexts {
		if reflect.DeepEqual(c, m.c) {
			return m.ctx
		}
	}
	panic(fmt.Sprintf("no context for: %#v", c))
}

func unregisterContext(c *Ctx) {
	requestMu.Lock()
	defer requestMu.Unlock()
	n := 0
	for _, m := range requestContexts {
		if m.ctx == c {
			continue
		}
		requestContexts[n] = m
		n++
	}
	requestContexts = requestContexts[:n]
}
