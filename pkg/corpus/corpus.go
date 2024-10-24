// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// Corpus object represents a set of syzkaller-found programs that
// cover the kernel up to the currently reached frontiers.
type Corpus struct {
	ctx      context.Context
	mu       sync.RWMutex
	progsMap map[string]*Item
	signal   signal.Signal // total signal of all items
	cover    cover.Cover   // total coverage of all items
	updates  chan<- NewItemEvent

	*ProgramsList
	StatProgs  *stat.Val
	StatSignal *stat.Val
	StatCover  *stat.Val

	focusAreas []*focusAreaState
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
}

type FocusArea struct {
	Name     string // can be empty
	CoverPCs map[uint64]struct{}
	Weight   float64
}

func NewCorpus(ctx context.Context) *Corpus {
	return NewMonitoredCorpus(ctx, nil)
}

func NewMonitoredCorpus(ctx context.Context, updates chan<- NewItemEvent) *Corpus {
	corpus := &Corpus{
		ctx:          ctx,
		progsMap:     make(map[string]*Item),
		updates:      updates,
		ProgramsList: &ProgramsList{},
	}
	corpus.StatProgs = stat.New("corpus", "Number of test programs in the corpus", stat.Console,
		stat.Link("/corpus"), stat.Graph("corpus"), stat.LenOf(&corpus.progsMap, &corpus.mu))
	corpus.StatSignal = stat.New("signal", "Fuzzing signal in the corpus",
		stat.LenOf(&corpus.signal, &corpus.mu))
	corpus.StatCover = stat.New("coverage", "Source coverage in the corpus", stat.Console,
		stat.Link("/cover"), stat.Prometheus("syz_corpus_cover"), stat.LenOf(&corpus.cover, &corpus.mu))
	return corpus
}

// It may happen that a single program is relevant because of several
// sysalls. In that case, there will be several ItemUpdate entities.
type ItemUpdate struct {
	Call     int
	RawCover []uint64
}

// Item objects are to be treated as immutable, otherwise it's just
// too hard to synchonize accesses to them across the whole project.
// When Corpus updates one of its items, it saves a copy of it.
type Item struct {
	Sig     string
	Call    int
	Prog    *prog.Prog
	HasAny  bool // whether the prog contains squashed arguments
	Signal  signal.Signal
	Cover   []uint64
	Updates []ItemUpdate

	areas map[*focusAreaState]struct{}
}

func (item Item) StringCall() string {
	return item.Prog.CallName(item.Call)
}

type NewInput struct {
	Prog     *prog.Prog
	Call     int
	Signal   signal.Signal
	Cover    []uint64
	RawCover []uint64
}

type NewItemEvent struct {
	Sig      string
	Exists   bool
	ProgData []byte
	NewCover []uint64
}

// SetFocusAreas can only be called once on an empty corpus.
func (corpus *Corpus) SetFocusAreas(areas []FocusArea) {
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	if len(corpus.progsMap) > 0 {
		panic("SetFocusAreas() is called on a non-empty corpus")
	}
	for _, area := range areas {
		obj := &ProgramsList{}
		if len(areas) > 1 && area.Name != "" {
			// Only show extra statistics if there's more than one area.
			stat.New("corpus ["+area.Name+"]",
				fmt.Sprintf("Corpus programs of the focus area %q", area.Name),
				stat.Console, stat.Graph("corpus"),
				stat.LenOf(&obj.progs, &corpus.mu))
		}
		corpus.focusAreas = append(corpus.focusAreas, &focusAreaState{
			FocusArea:    area,
			ProgramsList: obj,
		})
	}
}

func (corpus *Corpus) Save(inp NewInput) {
	progData := inp.Prog.Serialize()
	sig := hash.String(progData)

	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	update := ItemUpdate{
		Call:     inp.Call,
		RawCover: inp.RawCover,
	}
	exists := false
	if old, ok := corpus.progsMap[sig]; ok {
		exists = true
		newSignal := old.Signal.Copy()
		newSignal.Merge(inp.Signal)
		var newCover cover.Cover
		newCover.Merge(old.Cover)
		newCover.Merge(inp.Cover)
		newItem := &Item{
			Sig:     sig,
			Prog:    old.Prog,
			Call:    old.Call,
			HasAny:  old.HasAny,
			Signal:  newSignal,
			Cover:   newCover.Serialize(),
			Updates: append([]ItemUpdate{}, old.Updates...),
			areas:   maps.Clone(old.areas),
		}
		const maxUpdates = 32
		if len(newItem.Updates) < maxUpdates {
			newItem.Updates = append(newItem.Updates, update)
		}
		corpus.progsMap[sig] = newItem
		corpus.applyFocusAreas(newItem, inp.Cover)
	} else {
		item := &Item{
			Sig:     sig,
			Call:    inp.Call,
			Prog:    inp.Prog,
			HasAny:  inp.Prog.ContainsAny(),
			Signal:  inp.Signal,
			Cover:   inp.Cover,
			Updates: []ItemUpdate{update},
		}
		corpus.progsMap[sig] = item
		corpus.applyFocusAreas(item, inp.Cover)
		corpus.saveProgram(inp.Prog, inp.Signal)
	}
	corpus.signal.Merge(inp.Signal)
	newCover := corpus.cover.MergeDiff(inp.Cover)
	if corpus.updates != nil {
		select {
		case <-corpus.ctx.Done():
		case corpus.updates <- NewItemEvent{
			Sig:      sig,
			Exists:   exists,
			ProgData: progData,
			NewCover: newCover,
		}:
		}
	}
}

func (corpus *Corpus) applyFocusAreas(item *Item, coverDelta []uint64) {
	for _, area := range corpus.focusAreas {
		matches := false
		for _, pc := range coverDelta {
			if _, ok := area.CoverPCs[pc]; ok {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		area.saveProgram(item.Prog, item.Signal)
		if item.areas == nil {
			item.areas = make(map[*focusAreaState]struct{})
			item.areas[area] = struct{}{}
		}
	}
}

func (corpus *Corpus) Signal() signal.Signal {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.signal.Copy()
}

func (corpus *Corpus) Items() []*Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		ret = append(ret, item)
	}
	return ret
}

func (corpus *Corpus) Item(sig string) *Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progsMap[sig]
}

type CallCov struct {
	Count int
	Cover cover.Cover
}

func (corpus *Corpus) CallCover() map[string]*CallCov {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	calls := make(map[string]*CallCov)
	for _, inp := range corpus.progsMap {
		call := inp.StringCall()
		if calls[call] == nil {
			calls[call] = new(CallCov)
		}
		cc := calls[call]
		cc.Count++
		cc.Cover.Merge(inp.Cover)
	}
	return calls
}
