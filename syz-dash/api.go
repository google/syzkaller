// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build appengine

package dash

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"appengine"
	ds "appengine/datastore"
	"github.com/google/syzkaller/dashboard"
)

func init() {
	http.Handle("/api", handlerWrapper(handleAPI))
}

var apiHandlers = map[string]func(c appengine.Context, r *http.Request) (interface{}, error){
	"poll_patches": handlePollPatches,
	"get_patches":  handleGetPatches,
	"add_crash":    handleAddCrash,
	"add_repro":    handleAddRepro,
}

func handleAPI(c appengine.Context, w http.ResponseWriter, r *http.Request) error {
	client := new(Client)
	if err := ds.Get(c, ds.NewKey(c, "Client", r.FormValue("client"), 0, nil), client); err != nil {
		return fmt.Errorf("unknown client")
	}
	if r.FormValue("key") != client.Key {
		return fmt.Errorf("unknown client")
	}
	method := r.FormValue("method")
	handler := apiHandlers[method]
	if handler == nil {
		return fmt.Errorf("unknown api method '%v'", method)
	}
	res, err := handler(c, r)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		json.NewEncoder(gz).Encode(res)
		gz.Close()
	} else {
		json.NewEncoder(w).Encode(res)
	}
	return nil
}

const (
	BugStatusNew = iota
	BugStatusReported
	BugStatusFixed
	BugStatusUnclear
	BugStatusClaimed
	BugStatusClosed = 1000 + iota
	BugStatusDeleted
)

func statusToString(status int) string {
	switch status {
	case BugStatusNew:
		return "new"
	case BugStatusReported:
		return "reported"
	case BugStatusFixed:
		return "fixed"
	case BugStatusUnclear:
		return "unclear"
	case BugStatusClaimed:
		return "claimed"
	case BugStatusClosed:
		return "closed"
	case BugStatusDeleted:
		return "deleted"
	default:
		panic(fmt.Sprintf("unknown status %v", status))
	}
}

func stringToStatus(status string) (int, error) {
	switch status {
	case "new":
		return BugStatusNew, nil
	case "reported":
		return BugStatusReported, nil
	case "fixed":
		return BugStatusFixed, nil
	case "unclear":
		return BugStatusUnclear, nil
	case "claimed":
		return BugStatusClaimed, nil
	case "closed":
		return BugStatusClosed, nil
	case "deleted":
		return BugStatusDeleted, nil
	default:
		return 0, fmt.Errorf("unknown status '%v'", status)
	}
}

type Client struct {
	Name string
	Key  string
}

type Bug struct {
	Version    int64
	Title      string
	Status     int
	Groups     []string
	ReportLink string
	Comment    string
	CVE        string
	Patches    []Patch
}

type Patch struct {
	Title string
	Time  time.Time
	Diff  int64
}

type Group struct {
	Title      string
	Seq        int64
	Bug        int64
	NumCrashes int64
	NumRepro   int64
	HasRepro   bool
	HasCRepro  bool
	FirstTime  time.Time
	LastTime   time.Time
	Managers   []string
}

func hash(s string) string {
	sig := sha1.Sum([]byte(s))
	return hex.EncodeToString(sig[:])
}

func (group *Group) DisplayTitle() string {
	t := group.Title
	if group.Seq != 0 {
		t += fmt.Sprintf(" (%v)", group.Seq)
	}
	return t
}

func (group *Group) Key(c appengine.Context) *ds.Key {
	return ds.NewKey(c, "Group", group.hash(), 0, nil)
}

func (group *Group) hash() string {
	return hash(fmt.Sprintf("%v-%v", group.Title, group.Seq))
}

type Crash struct {
	Manager string
	Tag     string
	Time    time.Time
	Log     int64
	Report  int64
}

type Repro struct {
	Crash
	Opts  string
	Prog  int64
	CProg int64
}

const (
	maxTextLen    = 100
	maxTitleLen   = 200
	maxLinkLen    = 1000
	maxOptsLen    = 1000
	maxCommentLen = 4000

	maxCrashes = 20
)

func handleAddCrash(c appengine.Context, r *http.Request) (interface{}, error) {
	req := new(dashboard.Crash)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal crash: %v", err)
	}
	addedBug := false
	var group *Group
	if err := ds.RunInTransaction(c, func(c appengine.Context) error {
		now := time.Now()
		addedBug = false
		manager := r.FormValue("client")
		crash := &Crash{
			Manager: limitLength(manager, maxTextLen),
			Tag:     limitLength(req.Tag, maxTextLen),
			Time:    now,
		}
		var err error
		if crash.Log, err = putText(c, "CrashLog", req.Log); err != nil {
			return err
		}
		if crash.Report, err = putText(c, "CrashReport", req.Report); err != nil {
			return err
		}

		group = &Group{Title: limitLength(req.Desc, maxTitleLen), Seq: 0}
		for {
			if err := ds.Get(c, group.Key(c), group); err != nil {
				if err != ds.ErrNoSuchEntity {
					return err
				}
				bug := &Bug{
					Title:  group.DisplayTitle(),
					Status: BugStatusNew,
					Groups: []string{group.hash()},
				}
				bugKey, err := ds.Put(c, ds.NewIncompleteKey(c, "Bug", nil), bug)
				if err != nil {
					return err
				}
				group.Bug = bugKey.IntID()
				group.NumCrashes = 1
				group.FirstTime = now
				group.LastTime = now
				group.Managers = []string{manager}
				if _, err := ds.Put(c, group.Key(c), group); err != nil {
					return err
				}
				addedBug = true
				break
			}
			bug := new(Bug)
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", group.Bug, nil), bug); err != nil {
				return err
			}
			if bug.Status < BugStatusClosed {
				group.NumCrashes++
				group.LastTime = now
				found := false
				for _, manager1 := range group.Managers {
					if manager1 == manager {
						found = true
						break
					}
				}
				if !found {
					group.Managers = append(group.Managers, manager)
				}
				if _, err := ds.Put(c, group.Key(c), group); err != nil {
					return err
				}
				break
			}
			group.Seq++
		}

		if _, err := ds.Put(c, ds.NewIncompleteKey(c, "Crash", group.Key(c)), crash); err != nil {
			return err
		}
		return nil
	}, &ds.TransactionOptions{XG: true}); err != nil {
		return nil, err
	}
	if addedBug {
		dropCached(c)
	}
	purgeOldCrashes(c, group)
	return nil, nil
}

func purgeOldCrashes(c appengine.Context, group *Group) int {
	if group.NumCrashes <= maxCrashes {
		return 0
	}
	var keys []*ds.Key
	var crashes []*Crash
	keys, err := ds.NewQuery("Crash").Ancestor(group.Key(c)).Order("Time").Limit(2000).GetAll(c, &crashes)
	if err != nil {
		c.Errorf("Error: failed to fetch purge group crashes: %v", err)
		return -1
	}
	if len(keys) <= maxCrashes {
		return 0
	}
	keys = keys[:len(keys)-maxCrashes]
	crashes = crashes[:len(crashes)-maxCrashes]
	nn := len(keys)
	for len(keys) != 0 {
		n := len(keys)
		if n > 200 {
			n = 200
		}
		var textKeys []*ds.Key
		for _, crash := range crashes[:n] {
			if crash.Log != 0 {
				textKeys = append(textKeys, ds.NewKey(c, "Text", "", crash.Log, nil))
			}
			if crash.Report != 0 {
				textKeys = append(textKeys, ds.NewKey(c, "Text", "", crash.Report, nil))
			}
		}
		if len(textKeys) != 0 {
			if err := ds.DeleteMulti(c, textKeys); err != nil {
				c.Errorf("Error: failed to delete old crash texts: %v", err)
				return -1
			}
		}
		if err := ds.DeleteMulti(c, keys[:n]); err != nil {
			c.Errorf("Error: failed to delete old crashes: %v", err)
			return -1
		}
		keys = keys[n:]
		crashes = crashes[n:]
	}
	c.Infof("deleted %v crashes '%v'", nn, group.Title)
	return nn
}

func handleAddRepro(c appengine.Context, r *http.Request) (interface{}, error) {
	req := new(dashboard.Repro)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal repro: %v", err)
	}
	if err := ds.RunInTransaction(c, func(c appengine.Context) error {
		now := time.Now()
		group := &Group{Title: limitLength(req.Crash.Desc, maxTitleLen), Seq: 0}
		for {
			if err := ds.Get(c, group.Key(c), group); err != nil {
				return err
			}
			bug := new(Bug)
			if err := ds.Get(c, ds.NewKey(c, "Bug", "", group.Bug, nil), bug); err != nil {
				return err
			}
			if bug.Status < BugStatusClosed {
				break
			}
			group.Seq++
		}
		group.NumRepro++
		group.LastTime = now
		if len(req.Prog) != 0 {
			group.HasRepro = true
		}
		if len(req.CProg) != 0 {
			group.HasCRepro = true
		}
		if _, err := ds.Put(c, group.Key(c), group); err != nil {
			return err
		}
		if !req.Reproduced {
			return nil
		}

		manager := r.FormValue("client")
		crash := &Crash{
			Manager: limitLength(manager, maxTextLen),
			Tag:     limitLength(req.Crash.Tag, maxTextLen),
			Time:    now,
		}
		var err error
		if crash.Log, err = putText(c, "CrashLog", req.Crash.Log); err != nil {
			return err
		}
		if crash.Report, err = putText(c, "CrashReport", req.Crash.Report); err != nil {
			return err
		}
		repro := &Repro{
			Crash: *crash,
			Opts:  limitLength(req.Opts, maxOptsLen),
		}
		if repro.Prog, err = putText(c, "ReproProg", req.Prog); err != nil {
			return err
		}
		if repro.CProg, err = putText(c, "ReproCProg", req.CProg); err != nil {
			return err
		}

		if _, err := ds.Put(c, ds.NewIncompleteKey(c, "Repro", group.Key(c)), repro); err != nil {
			return err
		}
		return nil
	}, &ds.TransactionOptions{XG: true}); err != nil {
		return nil, err
	}
	return nil, nil
}

func handlePollPatches(c appengine.Context, r *http.Request) (interface{}, error) {
	var bugs []*Bug
	if _, err := ds.NewQuery("Bug").Filter("Status <", BugStatusClosed).GetAll(c, &bugs); err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %v", err)
	}
	var maxTime time.Time
	for _, bug := range bugs {
		for _, patch := range bug.Patches {
			if maxTime.Before(patch.Time) {
				maxTime = patch.Time
			}
		}
	}
	return fmt.Sprint(maxTime.UnixNano()), nil
}

func handleGetPatches(c appengine.Context, r *http.Request) (interface{}, error) {
	var bugs []*Bug
	if _, err := ds.NewQuery("Bug").Filter("Status <", BugStatusClosed).GetAll(c, &bugs); err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %v", err)
	}
	var patches []dashboard.Patch
	for _, bug := range bugs {
		for _, patch := range bug.Patches {
			diff, err := getText(c, patch.Diff)
			if err != nil {
				return nil, err
			}
			patches = append(patches, dashboard.Patch{
				Title: patch.Title,
				Diff:  diff,
			})
		}
	}
	return patches, nil
}

type GetPatchesResponse struct {
	Hash    string
	Patches []*Patch
	Ignores []string
}

type Text struct {
	Tag  string // any informative tag
	Text []byte // gzip-compressed text
}

func putText(c appengine.Context, tag string, data []byte) (int64, error) {
	if len(data) == 0 {
		return 0, nil
	}
	const (
		maxTextLen       = 2 << 20
		maxCompressedLen = 1000 << 10 // datastore entity limit is 1MB
	)
	if len(data) > maxTextLen {
		data = data[:maxTextLen]
	}
	b := new(bytes.Buffer)
	for {
		z, _ := gzip.NewWriterLevel(b, gzip.BestCompression)
		z.Write(data)
		z.Close()
		if len(b.Bytes()) < maxCompressedLen {
			break
		}
		data = data[:len(data)/10*9]
		b.Reset()
	}
	text := &Text{
		Tag:  tag,
		Text: b.Bytes(),
	}
	key, err := ds.Put(c, ds.NewIncompleteKey(c, "Text", nil), text)
	if err != nil {
		return 0, err
	}
	return key.IntID(), nil
}

func getText(c appengine.Context, id int64) ([]byte, error) {
	text := new(Text)
	if err := ds.Get(c, ds.NewKey(c, "Text", "", id, nil), text); err != nil {
		return nil, err
	}
	d, err := gzip.NewReader(bytes.NewBuffer(text.Text))
	if err != nil {
		return nil, fmt.Errorf("failed to read text: %v", err)
	}
	data, err := ioutil.ReadAll(d)
	if err != nil {
		return nil, fmt.Errorf("failed to read text: %v", err)
	}
	return data, nil
}

// limitLength essentially does return s[:max],
// but it ensures that we dot not split UTF-8 rune in half.
// Otherwise appengine python scripts will break badly.
func limitLength(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	for {
		s = s[:max]
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			return s
		}
		max--
	}
}
