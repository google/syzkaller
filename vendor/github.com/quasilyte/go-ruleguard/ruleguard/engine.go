package ruleguard

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"strings"
	"sync"

	"github.com/quasilyte/go-ruleguard/ruleguard/quasigo"
	"github.com/quasilyte/go-ruleguard/ruleguard/typematch"
)

type engine struct {
	state *engineState

	ruleSet *goRuleSet
}

func newEngine() *engine {
	return &engine{
		state: newEngineState(),
	}
}

func (e *engine) Load(ctx *ParseContext, filename string, r io.Reader) error {
	config := rulesParserConfig{
		state: e.state,
		ctx:   ctx,
		importer: newGoImporter(e.state, goImporterConfig{
			fset:         ctx.Fset,
			debugImports: ctx.DebugImports,
			debugPrint:   ctx.DebugPrint,
		}),
		itab: typematch.NewImportsTab(stdlibPackages),
	}
	p := newRulesParser(config)
	rset, err := p.ParseFile(filename, r)
	if err != nil {
		return err
	}

	if e.ruleSet == nil {
		e.ruleSet = rset
	} else {
		combinedRuleSet, err := mergeRuleSets([]*goRuleSet{e.ruleSet, rset})
		if err != nil {
			return err
		}
		e.ruleSet = combinedRuleSet
	}

	return nil
}

func (e *engine) Run(ctx *RunContext, f *ast.File) error {
	if e.ruleSet == nil {
		return errors.New("used Run() with an empty rule set; forgot to call Load() first?")
	}
	rset := cloneRuleSet(e.ruleSet)
	return newRulesRunner(ctx, e.state, rset).run(f)
}

// engineState is a shared state inside the engine.
type engineState struct {
	env *quasigo.Env

	typeByFQNMu sync.RWMutex
	typeByFQN   map[string]types.Type

	pkgCacheMu sync.RWMutex
	// pkgCache contains all imported packages, from any importer.
	pkgCache map[string]*types.Package
}

func newEngineState() *engineState {
	env := quasigo.NewEnv()
	state := &engineState{
		env:      env,
		pkgCache: make(map[string]*types.Package),
		typeByFQN: map[string]types.Type{
			// Predeclared types.
			`error`:      types.Universe.Lookup("error").Type(),
			`bool`:       types.Typ[types.Bool],
			`int`:        types.Typ[types.Int],
			`int8`:       types.Typ[types.Int8],
			`int16`:      types.Typ[types.Int16],
			`int32`:      types.Typ[types.Int32],
			`int64`:      types.Typ[types.Int64],
			`uint`:       types.Typ[types.Uint],
			`uint8`:      types.Typ[types.Uint8],
			`uint16`:     types.Typ[types.Uint16],
			`uint32`:     types.Typ[types.Uint32],
			`uint64`:     types.Typ[types.Uint64],
			`uintptr`:    types.Typ[types.Uintptr],
			`string`:     types.Typ[types.String],
			`float32`:    types.Typ[types.Float32],
			`float64`:    types.Typ[types.Float64],
			`complex64`:  types.Typ[types.Complex64],
			`complex128`: types.Typ[types.Complex128],
			// Predeclared aliases (provided for convenience).
			`byte`: types.Typ[types.Uint8],
			`rune`: types.Typ[types.Int32],
		},
	}
	initEnv(state, env)
	return state
}

func (state *engineState) GetCachedPackage(pkgPath string) *types.Package {
	state.pkgCacheMu.RLock()
	pkg := state.pkgCache[pkgPath]
	state.pkgCacheMu.RUnlock()
	return pkg
}

func (state *engineState) AddCachedPackage(pkgPath string, pkg *types.Package) {
	state.pkgCacheMu.Lock()
	state.pkgCache[pkgPath] = pkg
	state.pkgCacheMu.Unlock()
}

func (state *engineState) FindType(importer *goImporter, currentPkg *types.Package, fqn string) (types.Type, error) {
	// TODO(quasilyte): we can pre-populate the cache during the Load() phase.
	// If we inspect the AST of a user function, all constant FQN can be preloaded.
	// It could be a good thing as Load() is not expected to be executed in
	// concurrent environment, so write-locking is not a big deal there.

	state.typeByFQNMu.RLock()
	cachedType, ok := state.typeByFQN[fqn]
	state.typeByFQNMu.RUnlock()
	if ok {
		return cachedType, nil
	}

	// Code below is under a write critical section.
	state.typeByFQNMu.Lock()
	defer state.typeByFQNMu.Unlock()

	typ, err := state.findTypeNoCache(importer, currentPkg, fqn)
	if err != nil {
		return nil, err
	}
	state.typeByFQN[fqn] = typ
	return typ, nil
}

func (state *engineState) findTypeNoCache(importer *goImporter, currentPkg *types.Package, fqn string) (types.Type, error) {
	pos := strings.LastIndexByte(fqn, '.')
	if pos == -1 {
		return nil, fmt.Errorf("%s is not a valid FQN", fqn)
	}
	pkgPath := fqn[:pos]
	objectName := fqn[pos+1:]
	var pkg *types.Package
	if directDep := findDependency(currentPkg, pkgPath); directDep != nil {
		pkg = directDep
	} else {
		loadedPkg, err := importer.Import(pkgPath)
		if err != nil {
			return nil, err
		}
		pkg = loadedPkg
	}
	obj := pkg.Scope().Lookup(objectName)
	if obj == nil {
		return nil, fmt.Errorf("%s is not found in %s", objectName, pkgPath)
	}
	typ := obj.Type()
	state.typeByFQN[fqn] = typ
	return typ, nil
}
