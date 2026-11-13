// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestState struct {
	t     *testing.T
	dir   string
	state *State
}

func MakeTestState(t *testing.T) *TestState {
	t.Parallel()
	dir := t.TempDir()
	state, err := Make(dir)
	if err != nil {
		t.Fatalf("failed to make state: %v", err)
	}
	return &TestState{t, dir, state}
}

func (ts *TestState) Reload() {
	ts.state.Flush()
	state, err := Make(ts.dir)
	if err != nil {
		ts.t.Fatalf("failed to make state: %v", err)
	}
	ts.state = state
}

func (ts *TestState) Connect(name, domain string, fresh bool, calls []string, corpus [][]byte) {
	ts.t.Helper()
	if err := ts.state.Connect(name, "", domain, fresh, calls, corpus); err != nil {
		ts.t.Fatalf("Connect failed: %v", err)
	}
}

func (ts *TestState) Sync(name string, add [][]byte, del []string) (string, []rpctype.HubInput, int) {
	ts.t.Helper()
	domain, inputs, pending, err := ts.state.Sync(name, add, del)
	if err != nil {
		ts.t.Fatalf("Sync failed: %v", err)
	}
	slices.SortFunc(inputs, func(a, b rpctype.HubInput) int {
		if a.Domain != b.Domain {
			return cmp.Compare(a.Domain, b.Domain)
		}
		return cmp.Compare(string(a.Prog), string(b.Prog))
	})
	return domain, inputs, pending
}

func (ts *TestState) AddRepro(name string, repro []byte) {
	ts.t.Helper()
	if err := ts.state.AddRepro(name, repro); err != nil {
		ts.t.Fatalf("AddRepro failed: %v", err)
	}
}

func (ts *TestState) PendingRepro(name string) []byte {
	ts.t.Helper()
	repro, err := ts.state.PendingRepro(name)
	if err != nil {
		ts.t.Fatalf("PendingRepro failed: %v", err)
	}
	return repro
}

func TestBasic(t *testing.T) {
	st := MakeTestState(t)

	if _, _, _, err := st.state.Sync("foo", nil, nil); err == nil {
		t.Fatalf("synced with unconnected manager")
	}
	calls := []string{"read", "write"}
	st.Connect("foo", "", false, calls, nil)
	st.Sync("foo", nil, nil)
}

func TestInvalidManagerName(t *testing.T) {
	st := MakeTestState(t)
	for _, name := range []string{
		"",
		".",
		"..",
		".hidden",
		"-dash",
		"foo/bar",
		`foo\bar`,
		"foo/../../escape",
		"../escape",
		strings.Repeat("a", 102),
	} {
		assert.Error(t, st.state.Connect(name, "", "domain", true, []string{"open"}, nil), "name=%q", name)
	}
}

func TestRepro(t *testing.T) {
	st := MakeTestState(t)

	st.Connect("foo", "", false, []string{"open", "read", "write"}, nil)
	st.Connect("bar", "", false, []string{"open", "read", "close"}, nil)

	expectPendingRepro := func(name, result string) {
		t.Helper()
		repro := st.PendingRepro(name)
		if string(repro) != result {
			t.Fatalf("got %q, want %q", string(repro), result)
		}
	}
	expectPendingRepro("foo", "")
	expectPendingRepro("bar", "")
	st.AddRepro("foo", []byte("open()"))
	expectPendingRepro("foo", "")
	expectPendingRepro("bar", "open()")
	expectPendingRepro("bar", "")

	// This repro is already present.
	st.AddRepro("bar", []byte("open()"))
	st.AddRepro("bar", []byte("read()"))
	st.AddRepro("bar", []byte("open()\nread()"))
	// This does not satisfy foo's call set.
	st.AddRepro("bar", []byte("close()"))
	expectPendingRepro("bar", "")

	// Check how persistence works.
	st.Reload()
	st.Connect("foo", "", false, []string{"open", "read", "write"}, nil)
	st.Connect("bar", "", false, []string{"open", "read", "close"}, nil)
	expectPendingRepro("bar", "")
	expectPendingRepro("foo", "read()")
	expectPendingRepro("foo", "open()\nread()")
	expectPendingRepro("foo", "")
}

func TestDomain(t *testing.T) {
	st := MakeTestState(t)

	st.Connect("client0", "", false, []string{"open"}, nil)
	st.Connect("client1", "domain1", false, []string{"open"}, nil)
	st.Connect("client2", "domain2", false, []string{"open"}, nil)
	st.Connect("client3", "domain3", false, []string{"open"}, nil)
	{
		domain, inputs, pending := st.Sync("client0", [][]byte{[]byte("open(0x0)")}, nil)
		if domain != "" || len(inputs) != 0 || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
	}
	{
		domain, inputs, pending := st.Sync("client0", [][]byte{[]byte("open(0x1)")}, nil)
		if domain != "" || len(inputs) != 0 || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
	}
	{
		domain, inputs, pending := st.Sync("client1", [][]byte{[]byte("open(0x2)"), []byte("open(0x1)")}, nil)
		if domain != "domain1" || pending != 0 {
			t.Fatalf("bad sync result: %v, %v, %v", domain, inputs, pending)
		}
		require.Equal(t, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
		}, inputs)
	}
	{
		_, inputs, _ := st.Sync("client2", [][]byte{[]byte("open(0x3)")}, nil)
		require.Equal(t, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
			{Domain: "domain1", Prog: []byte("open(0x1)")},
			{Domain: "domain1", Prog: []byte("open(0x2)")},
		}, inputs)
	}
	{
		_, inputs, _ := st.Sync("client0", nil, nil)
		require.Equal(t, []rpctype.HubInput{
			{Domain: "domain1", Prog: []byte("open(0x2)")},
			{Domain: "domain2", Prog: []byte("open(0x3)")},
		}, inputs)
	}
	st.Reload()
	st.Connect("client3", "domain3", false, []string{"open"}, nil)
	{
		_, inputs, _ := st.Sync("client3", nil, nil)
		require.Equal(t, []rpctype.HubInput{
			{Domain: "", Prog: []byte("open(0x0)")},
			{Domain: "domain1", Prog: []byte("open(0x1)")},
			{Domain: "domain1", Prog: []byte("open(0x2)")},
			{Domain: "domain2", Prog: []byte("open(0x3)")},
		}, inputs)
	}
}

func TestCorpusPurgeAndRefCount(t *testing.T) {
	st := MakeTestState(t)

	p0 := []byte("open(0x0)")
	p1 := []byte("open(0x1)")
	p2 := []byte("open(0x2)")
	sig0 := hash.String(p0)
	sig1 := hash.String(p1)
	sig2 := hash.String(p2)

	// Connect mgr1 with p0 and p1, and mgr2 with p1 and p2.
	st.Connect("mgr1", "d1", true, []string{"open"}, [][]byte{p0, p1})
	st.Connect("mgr2", "d2", true, []string{"open"}, [][]byte{p1, p2})
	assert.Len(t, st.state.Corpus.Records, 3)

	// Deleting p1 from mgr1 keeps p1 in hub corpus because mgr2 still holds it.
	st.Sync("mgr1", nil, []string{sig1, sig1, "non-existent-sig"})
	assert.Len(t, st.state.Corpus.Records, 3)
	assert.Contains(t, st.state.Corpus.Records, sig1)

	// Deleting p1 from mgr2 drops its ref count to 0 and removes it from hub corpus.
	st.Sync("mgr2", nil, []string{sig1})
	assert.Len(t, st.state.Corpus.Records, 2)
	assert.NotContains(t, st.state.Corpus.Records, sig1)

	// Re-adding p1 via Sync works and makes it visible to mgr1 again.
	st.Sync("mgr2", [][]byte{p1}, nil)
	assert.Len(t, st.state.Corpus.Records, 3)
	_, inputs, _ := st.Sync("mgr1", nil, nil)
	require.Equal(t, []rpctype.HubInput{
		{Domain: "d2", Prog: p1},
	}, inputs)

	// Reconnecting mgr1 with p1 keeps p1 (shared with mgr2) and drops p0 (only held by mgr1).
	st.Connect("mgr1", "d1", false, []string{"open"}, [][]byte{p1})
	assert.Len(t, st.state.Corpus.Records, 2)
	assert.NotContains(t, st.state.Corpus.Records, sig0)
	assert.Contains(t, st.state.Corpus.Records, sig1)
	assert.Contains(t, st.state.Corpus.Records, sig2)

	// Age mgr2's seq file past 30 days and reload state from disk:
	// Make() should purge mgr2 (removing p2) while keeping p1 (still held by active mgr1).
	oldTime := time.Now().Add(-31 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(st.state.Managers["mgr2"].corpusSeqFile, oldTime, oldTime))
	st.Reload()
	assert.Len(t, st.state.Corpus.Records, 1)
	assert.Contains(t, st.state.Corpus.Records, sig1)
	assert.NotContains(t, st.state.Corpus.Records, sig2)
}

func TestNewCallsAfterConnect(t *testing.T) {
	st := MakeTestState(t)

	// mgr1 connects knowing only "open".
	st.Connect("mgr1", "d1", true, []string{"open"}, nil)
	// mgr2 connects later introducing a previously unseen call "ioctl".
	st.Connect("mgr2", "d2", true, []string{"open", "ioctl"}, [][]byte{
		[]byte("open(0x0)\nioctl(0x1)"),
		[]byte("open(0x2)"),
	})

	// mgr1 should only receive the program that uses "open", not "ioctl".
	_, inputs, _ := st.Sync("mgr1", nil, nil)
	require.Equal(t, []rpctype.HubInput{
		{Domain: "d2", Prog: []byte("open(0x2)")},
	}, inputs)

	// Same for repros: a repro with "ioctl" is skipped for mgr1.
	st.AddRepro("mgr2", []byte("ioctl(0x1)"))
	assert.Empty(t, st.PendingRepro("mgr1"))
}

func TestBatchSync(t *testing.T) {
	st := MakeTestState(t)

	const totalProgs = 170
	progs := make([][]byte, totalProgs)
	for i := range totalProgs {
		progs[i] = []byte(fmt.Sprintf("open(0x%x)", i))
	}
	drainSync := func(name string) [][]byte {
		var res [][]byte
		for {
			_, inputs, more := st.Sync(name, nil, nil)
			for _, inp := range inputs {
				res = append(res, inp.Prog)
			}
			if len(inputs)+more == 0 {
				break
			}
		}
		return res
	}

	// 1. mgr1 connects (fresh) with 0..150; mgr2 connects (fresh) with an empty corpus
	// and drains Sync => receives exactly 0..150.
	st.Connect("mgr1", "d1", true, []string{"open"}, progs[:150])
	st.Connect("mgr2", "d2", true, []string{"open"}, nil)
	assert.Len(t, st.state.Corpus.Records, 150)
	assert.ElementsMatch(t, progs[:150], drainSync("mgr2"))

	// 2. mgr1 reconnects (fresh=false) with 10..170 => hub corpus has 160 programs,
	// and mgr2 receives only the 20 new ones (150..170).
	st.Connect("mgr1", "d1", false, []string{"open"}, progs[10:170])
	assert.Len(t, st.state.Corpus.Records, 160)
	assert.ElementsMatch(t, progs[150:170], drainSync("mgr2"))

	// 3. mgr2 reconnects with fresh=false => receives nothing;
	// with fresh=true => receives 10..170 again.
	st.Connect("mgr2", "d2", false, []string{"open"}, nil)
	assert.Empty(t, drainSync("mgr2"))

	st.Connect("mgr2", "d2", true, []string{"open"}, nil)
	assert.ElementsMatch(t, progs[10:170], drainSync("mgr2"))
}

func TestBatchSyncSkipsNonMatchingWatermark(t *testing.T) {
	st := MakeTestState(t)

	// foo adds 100 programs matching bar ("open"), then 100 programs NOT matching bar
	// ("ioctl"), then 50 more matching programs ("open").
	st.Connect("foo", "", true, []string{"open", "ioctl"}, nil)
	st.Connect("bar", "", true, []string{"open"}, nil)

	batch1 := make([][]byte, 100)
	for i := range batch1 {
		batch1[i] = []byte(fmt.Sprintf("open(0x%x)", i))
	}
	nonMatching := make([][]byte, 100)
	for i := range nonMatching {
		nonMatching[i] = []byte(fmt.Sprintf("ioctl(0x%x)", i))
	}
	batch2 := make([][]byte, 50)
	for i := range batch2 {
		batch2[i] = []byte(fmt.Sprintf("open(0x%x)", 100+i))
	}
	st.Sync("foo", batch1, nil)
	st.Sync("foo", nonMatching, nil)
	st.Sync("foo", batch2, nil)

	// First Sync returns batch1 (seq 1..100) and advances bar.corpusSeq past the
	// 100 non-matching "ioctl" programs (seq 101..200) to 200.
	_, inputs, more := st.Sync("bar", nil, nil)
	assert.Len(t, inputs, 100)
	assert.Equal(t, 50, more)
	assert.Equal(t, uint64(200), st.state.Managers["bar"].corpusSeq)

	// Second Sync jumps directly to seq 201 and returns batch2.
	_, inputs, more = st.Sync("bar", nil, nil)
	assert.Len(t, inputs, 50)
	assert.Equal(t, 0, more)
	assert.Equal(t, uint64(250), st.state.Managers["bar"].corpusSeq)
}

func TestCompactCorpusOrder(t *testing.T) {
	st := MakeTestState(t)

	const total = 1100
	progs := make([][]byte, total)
	sigs := make([]string, total)
	for i := range total {
		progs[i] = []byte(fmt.Sprintf("open(0x%x)", i))
		sigs[i] = hash.String(progs[i])
	}
	st.Connect("mgr1", "d1", true, []string{"open"}, progs)
	assert.Len(t, st.state.corpusOrder, total)

	// Delete 1050 programs (> 1024 threshold) to trigger maybeCompactCorpusOrder.
	st.Sync("mgr1", nil, sigs[:1050])
	assert.Len(t, st.state.Corpus.Records, 50)
	assert.Len(t, st.state.corpusOrder, 50)

	// A new manager syncing receives only the remaining 50 programs.
	st.Connect("mgr2", "d2", true, []string{"open"}, nil)
	_, inputs, more := st.Sync("mgr2", nil, nil)
	assert.Equal(t, 0, more)
	assert.Len(t, inputs, 50)
}

func TestCorruptedDBEntries(t *testing.T) {
	st := MakeTestState(t)

	validProg := []byte("open(0x0)")
	validSig := hash.String(validProg)
	st.Connect("mgr1", "", true, []string{"open"}, [][]byte{validProg})

	// Inject corrupted records directly into Corpus DB and reload:
	// 1. Unparseable program call set.
	badSyntax := []byte("not a valid program")
	st.state.Corpus.Save(hash.String(badSyntax), badSyntax, 10)
	// 2. Program with > prog.MaxCalls calls.
	tooManyCalls := []byte(strings.Repeat("open(0x0)\n", prog.MaxCalls+1))
	st.state.Corpus.Save(hash.String(tooManyCalls), tooManyCalls, 11)
	// 3. Record whose key does not match its content hash.
	st.state.Corpus.Save(hash.String([]byte("other")), []byte("open(0x1)"), 12)

	st.Reload()
	assert.Len(t, st.state.Corpus.Records, 1)
	assert.Contains(t, st.state.Corpus.Records, validSig)
}

func TestCapRecordsCountsMatchingInputs(t *testing.T) {
	st := MakeTestState(t)

	st.Connect("mgr1", "d1", true, []string{"open", "ioctl"}, nil)
	st.Connect("mgr2", "d2", true, []string{"open"}, nil)

	openID := st.state.callID("open")
	ioctlID := st.state.callID("ioctl")

	const (
		matchingCount = 50
		capCount      = 100000
	)
	var nextIdx int
	addRecord := func(call string, callID uint32) {
		idx := nextIdx
		nextIdx++
		seq := uint64(idx + 1)
		progText := []byte(fmt.Sprintf("%s(0x%x)", call, idx))
		key := fmt.Sprintf("key-%06d", idx)
		st.state.Corpus.Records[key] = db.Record{Val: progText, Seq: seq}
		st.state.corpusMeta[key] = corpusMeta{key: key, calls: []uint32{callID}, refs: 1}
		st.state.corpusOrder = append(st.state.corpusOrder, seqEntry{key: key, seq: seq})
		st.state.corpusSeq = seq
	}

	// Populate 50 matching ("open") records followed by 100,000 non-matching ("ioctl")
	// records so len(corpusOrder) > capRecords (100,000), while only 50 records match mgr2.
	for range matchingCount {
		addRecord("open", openID)
	}
	for range capCount {
		addRecord("ioctl", ioctlID)
	}

	// mgr2 should still receive all 50 matching records despite the 100,000 non-matching tail.
	_, inputs, more := st.Sync("mgr2", nil, nil)
	assert.Equal(t, 0, more)
	assert.Len(t, inputs, matchingCount)
	assert.Equal(t, st.state.corpusSeq, st.state.Managers["mgr2"].capCheckedSeq)

	// Append 100,000 more matching ("open") records so total matching records is 100,050
	// (> capRecords = 100,000). A fresh manager should skip the first 50 matching records
	// and the 100,000 non-matching records, starting at index 100,050 (seq 100,051).
	base := nextIdx
	for range capCount {
		addRecord("open", openID)
	}
	st.Connect("mgr3", "d3", true, []string{"open"}, nil)
	_, inputs, more = st.Sync("mgr3", nil, nil)
	assert.Equal(t, 99900, more)
	assert.Len(t, inputs, 100)
	assert.Equal(t, st.state.corpusSeq, st.state.Managers["mgr3"].capCheckedSeq)
	assert.Contains(t, inputs, rpctype.HubInput{Prog: []byte(fmt.Sprintf("open(0x%x)", base))})
	assert.NotContains(t, inputs, rpctype.HubInput{Prog: []byte("open(0x0)")})
}
