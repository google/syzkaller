package goanalysis

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/objectpath"

	"github.com/golangci/golangci-lint/internal/cache"
)

type Fact struct {
	Path string // non-empty only for object facts
	Fact analysis.Fact
}

func (act *action) loadCachedFacts() bool {
	if act.loadCachedFactsDone { // can't be set in parallel
		return act.loadCachedFactsOk
	}

	res := func() bool {
		if act.isInitialPkg {
			return true // load cached facts only for non-initial packages
		}

		if len(act.a.FactTypes) == 0 {
			return true // no need to load facts
		}

		return act.loadPersistedFacts()
	}()
	act.loadCachedFactsDone = true
	act.loadCachedFactsOk = res
	return res
}

func (act *action) persistFactsToCache() error {
	analyzer := act.a
	if len(analyzer.FactTypes) == 0 {
		return nil
	}

	// Merge new facts into the package and persist them.
	var facts []Fact
	for key, fact := range act.packageFacts {
		if key.pkg != act.pkg.Types {
			// The fact is from inherited facts from another package
			continue
		}
		facts = append(facts, Fact{
			Path: "",
			Fact: fact,
		})
	}
	for key, fact := range act.objectFacts {
		obj := key.obj
		if obj.Pkg() != act.pkg.Types {
			// The fact is from inherited facts from another package
			continue
		}

		path, err := objectpath.For(obj)
		if err != nil {
			// The object is not globally addressable
			continue
		}

		facts = append(facts, Fact{
			Path: string(path),
			Fact: fact,
		})
	}

	factsCacheDebugf("Caching %d facts for package %q and analyzer %s", len(facts), act.pkg.Name, act.a.Name)

	return act.r.pkgCache.Put(act.pkg, cache.HashModeNeedAllDeps, factCacheKey(analyzer), facts)
}

func (act *action) loadPersistedFacts() bool {
	var facts []Fact

	err := act.r.pkgCache.Get(act.pkg, cache.HashModeNeedAllDeps, factCacheKey(act.a), &facts)
	if err != nil {
		if !errors.Is(err, cache.ErrMissing) && !errors.Is(err, io.EOF) {
			act.r.log.Warnf("Failed to get persisted facts: %s", err)
		}

		factsCacheDebugf("No cached facts for package %q and analyzer %s", act.pkg.Name, act.a.Name)
		return false
	}

	factsCacheDebugf("Loaded %d cached facts for package %q and analyzer %s", len(facts), act.pkg.Name, act.a.Name)

	for _, f := range facts {
		if f.Path == "" { // this is a package fact
			key := packageFactKey{act.pkg.Types, act.factType(f.Fact)}
			act.packageFacts[key] = f.Fact
			continue
		}
		obj, err := objectpath.Object(act.pkg.Types, objectpath.Path(f.Path))
		if err != nil {
			// Be lenient about these errors. For example, when
			// analyzing io/ioutil from source, we may get a fact
			// for methods on the devNull type, and objectpath
			// will happily create a path for them. However, when
			// we later load io/ioutil from export data, the path
			// no longer resolves.
			//
			// If an exported type embeds the unexported type,
			// then (part of) the unexported type will become part
			// of the type information and our path will resolve
			// again.
			continue
		}
		factKey := objectFactKey{obj, act.factType(f.Fact)}
		act.objectFacts[factKey] = f.Fact
	}

	return true
}

func factCacheKey(a *analysis.Analyzer) string {
	return fmt.Sprintf("%s/facts", a.Name)
}
