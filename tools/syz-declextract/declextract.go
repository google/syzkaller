// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/declextract"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/targets"
	clangtoolimpl "github.com/google/syzkaller/tools/clang/declextract"
	"golang.org/x/sync/errgroup"
)

// The target we currently assume for extracted descriptions.
var target = targets.Get(targets.Linux, targets.AMD64)

func main() {
	var (
		flagConfig   = flag.String("config", "", "manager config file")
		flagCoverage = flag.String("coverage", "", "syzbot coverage jsonl file")
		flagArches   = flag.String("arches", "", "comma-separated list of arches to extract (all if empty)")
	)
	defer tool.Init()()
	mgrcfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		tool.Fail(err)
	}
	loadProbeInfo := func() (*ifaceprobe.Info, error) {
		return probe(mgrcfg, *flagConfig)
	}
	cfg := &config{
		archList:      *flagArches,
		autoFile:      filepath.FromSlash("sys/linux/auto.txt"),
		coverFile:     *flagCoverage,
		loadProbeInfo: loadProbeInfo,
		Config: &clangtool.Config{
			Tool:       clangtoolimpl.Tool,
			KernelSrc:  mgrcfg.KernelSrc,
			KernelObj:  mgrcfg.KernelObj,
			CacheFile:  filepath.Join(mgrcfg.Workdir, "declextract.cache"),
			DebugTrace: os.Stderr,
		},
	}
	if _, err := run(cfg); err != nil {
		tool.Fail(err)
	}
}

type config struct {
	archList      string
	autoFile      string
	coverFile     string
	loadProbeInfo func() (*ifaceprobe.Info, error)
	*clangtool.Config
}

func run(cfg *config) (*declextract.Result, error) {
	out, probeInfo, coverage, syscallRename, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(cfg.autoFile)
	overlays, err := discoverOverlays(dir, cfg.autoFile)
	if err != nil {
		return nil, err
	}
	for _, spec := range overlays {
		overlayRes, err := declextract.RunOverlay(out, probeInfo, spec.roots,
			spec.excludeStructs, spec.excludeEnums, spec.arches, cfg.DebugTrace)
		if err != nil {
			return nil, err
		}
		if err := osutil.WriteFile(spec.overlayFile, overlayRes.Descriptions); err != nil {
			return nil, err
		}
	}
	res, err := declextract.Run(out, probeInfo, coverage, syscallRename, cfg.DebugTrace)
	if err != nil {
		return nil, err
	}
	if err := osutil.WriteFile(cfg.autoFile, res.Descriptions); err != nil {
		return nil, err
	}
	if err := osutil.WriteFile(cfg.autoFile+".info", serialize(res.Interfaces)); err != nil {
		return nil, err
	}
	// In order to remove unused bits of the descriptions, we need to write them out first,
	// and then parse all descriptions back b/c auto descriptions use some types defined
	// by manual descriptions (compiler.CollectUnused requires complete descriptions).
	// This also canonicalizes them b/c new lines are added during parsing.
	eh, errors := errorHandler()
	desc := ast.ParseGlob(filepath.Join(dir, "*.txt"), eh)
	if desc == nil {
		return nil, fmt.Errorf("failed to parse descriptions\n%s", errors.Bytes())
	}
	// Need to clone descriptions b/c CollectUnused changes them slightly during type checking.
	unusedNodes, err := compiler.CollectUnused(desc.Clone(), target, eh)
	if err != nil {
		return nil, fmt.Errorf("failed to typecheck descriptions: %w\n%s", err, errors.Bytes())
	}
	consts := compiler.ExtractConsts(desc.Clone(), target, eh)
	if consts == nil {
		return nil, fmt.Errorf("failed to typecheck descriptions: %w\n%s", err, errors.Bytes())
	}
	finishInterfaces(res.Interfaces, consts, cfg.autoFile)
	if err := osutil.WriteFile(cfg.autoFile+".info", serialize(res.Interfaces)); err != nil {
		return nil, err
	}
	removeUnusedNodes(desc, unusedNodes)
	// Second pass to remove unused defines/includes. This needs to be done after removing
	// other garbage b/c they may be used by other garbage.
	unusedConsts, err := compiler.CollectUnusedConsts(desc.Clone(), target, res.IncludeUse, eh)
	if err != nil {
		return nil, fmt.Errorf("failed to typecheck descriptions: %w\n%s", err, errors.Bytes())
	}
	removeUnusedNodes(desc, unusedConsts)

	generatedFiles := []string{cfg.autoFile}
	for _, spec := range overlays {
		generatedFiles = append(generatedFiles, spec.overlayFile)
	}
	for _, genFile := range generatedFiles {
		fileDesc := filterFile(desc, genFile)
		// We need re-parse them again b/c new lines are fixed up during parsing.
		formatted := ast.Format(ast.Parse(ast.Format(fileDesc), genFile, nil))
		if err := osutil.WriteFile(genFile, formatted); err != nil {
			return nil, err
		}
	}
	return res, nil
}

type overlaySpec struct {
	manualFile     string
	overlayFile    string
	roots          map[string]bool
	excludeStructs map[string]bool
	excludeEnums   map[string]bool
	arches         []string
}

func discoverOverlays(dir, autoFile string) ([]overlaySpec, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	eh, errors := errorHandler()
	parsed := make(map[string]*ast.Description)
	autoFiles := map[string]bool{autoFile: true}
	overlayTargets := make(map[string]string) // manualFile -> overlayFile
	for _, f := range files {
		if f == autoFile {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		desc := ast.Parse(data, f, eh)
		if desc == nil {
			return nil, fmt.Errorf("failed to parse %v:\n%s", f, errors.Bytes())
		}
		parsed[f] = desc
		for _, n := range desc.Nodes {
			if meta, ok := n.(*ast.Meta); ok && meta.Value.Ident == "overlay" && len(meta.Value.Args) == 1 {
				targetFile := filepath.Join(dir, meta.Value.Args[0].String)
				autoFiles[targetFile] = true
				overlayTargets[f] = targetFile
			}
		}
	}
	if len(overlayTargets) == 0 {
		return nil, nil
	}
	manualStructs, manualEnums := collectManualExclusions(parsed, autoFiles)
	var specs []overlaySpec
	for manualFile, overlayFile := range overlayTargets {
		specs = append(specs, buildOverlaySpec(manualFile, overlayFile, parsed[manualFile], manualStructs, manualEnums))
	}
	slices.SortFunc(specs, func(a, b overlaySpec) int {
		return strings.Compare(a.manualFile, b.manualFile)
	})
	return specs, nil
}

func collectManualExclusions(parsed map[string]*ast.Description,
	autoFiles map[string]bool) (map[string]bool, map[string]bool) {
	manualStructs := make(map[string]bool)
	manualEnums := make(map[string]bool)
	for f, desc := range parsed {
		if autoFiles[f] {
			continue
		}
		for _, n := range desc.Nodes {
			switch decl := n.(type) {
			case *ast.Struct:
				if !decl.IsOverride {
					manualStructs[decl.Name.Name] = true
				}
			case *ast.IntFlags:
				if !decl.IsOverride {
					manualEnums[decl.Name.Name] = true
				}
			case *ast.Resource:
				manualStructs[decl.Name.Name] = true
			case *ast.TypeDef:
				manualStructs[decl.Name.Name] = true
			}
		}
	}
	return manualStructs, manualEnums
}

func buildOverlaySpec(manualFile, overlayFile string, desc *ast.Description,
	manualStructs, manualEnums map[string]bool) overlaySpec {
	roots := make(map[string]bool)
	desc.Walk(ast.Recursive(func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.Type:
			if decl.Ident != "" {
				roots[decl.Ident] = true
			}
		case *ast.Struct:
			if decl.IsOverride {
				roots[decl.Name.Name] = true
			}
		case *ast.IntFlags:
			if decl.IsOverride {
				roots[decl.Name.Name] = true
			}
		case *ast.StrFlags:
			if decl.IsOverride {
				roots[decl.Name.Name] = true
			}
		}
		return true
	}))
	var arches []string
	for _, n := range desc.Nodes {
		if meta, ok := n.(*ast.Meta); ok && meta.Value.Ident == "arches" {
			for _, arg := range meta.Value.Args {
				arches = append(arches, arg.String)
			}
		}
	}
	return overlaySpec{
		manualFile:     manualFile,
		overlayFile:    overlayFile,
		roots:          roots,
		excludeStructs: manualStructs,
		excludeEnums:   manualEnums,
		arches:         arches,
	}
}

func removeUnusedNodes(desc *ast.Description, unusedNodes []ast.Node) {
	unused := make(map[string]bool)
	for _, n := range unusedNodes {
		pos, typ, name := n.Info()
		unused[pos.File+"/"+typ+"/"+name] = true
	}
	desc.Nodes = slices.DeleteFunc(desc.Nodes, func(n ast.Node) bool {
		pos, typ, name := n.Info()
		return unused[pos.File+"/"+typ+"/"+name]
	})
}

func filterFile(desc *ast.Description, targetFile string) *ast.Description {
	var nodes []ast.Node
	for _, n := range desc.Nodes {
		pos, _, _ := n.Info()
		if pos.File == targetFile {
			nodes = append(nodes, n)
		}
	}
	return &ast.Description{Nodes: nodes}
}

func prepare(cfg *config) (*declextract.Output, *ifaceprobe.Info, []*cover.FileCoverage,
	map[string][]string, error) {
	arches, err := tool.ParseArchList(target.OS, cfg.archList)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse arches flag: %w", err)
	}
	var eg errgroup.Group
	var out *declextract.Output
	eg.Go(func() error {
		var err error
		out, err = clangtool.Run[declextract.Output](cfg.Config)
		if err != nil {
			return err
		}
		return nil
	})
	var probeInfo *ifaceprobe.Info
	eg.Go(func() error {
		var err error
		probeInfo, err = cfg.loadProbeInfo()
		if err != nil {
			return fmt.Errorf("kernel probing failed: %w", err)
		}
		return nil
	})
	var syscallRename map[string][]string
	eg.Go(func() error {
		var err error
		syscallRename, err = buildSyscallRenameMap(cfg.KernelSrc, arches)
		if err != nil {
			return fmt.Errorf("failed to build syscall rename map: %w", err)
		}
		return nil
	})
	var coverage []*cover.FileCoverage
	eg.Go(func() error {
		if cfg.coverFile == "" {
			return nil
		}
		var err error
		coverage, err = loadCoverage(cfg.coverFile)
		return err
	})
	err = eg.Wait()
	return out, probeInfo, coverage, syscallRename, err
}

func loadCoverage(fileName string) ([]*cover.FileCoverage, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var coverage []*cover.FileCoverage
	for {
		elem := new(cover.FileCoverage)
		if err := dec.Decode(elem); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		coverage = append(coverage, elem)
	}
	return coverage, nil
}

func probe(cfg *mgrconfig.Config, cfgFile string) (*ifaceprobe.Info, error) {
	cacheFile := filepath.Join(cfg.Workdir, "interfaces.json")
	info, err := readProbeResult(cacheFile)
	if err == nil {
		return info, nil
	}
	_, err = osutil.RunCmd(30*time.Minute, "", filepath.Join(cfg.Syzkaller, "bin", "syz-manager"),
		"-config", cfgFile, "-mode", "iface-probe")
	if err != nil {
		return nil, err
	}
	return readProbeResult(cacheFile)
}

func readProbeResult(file string) (*ifaceprobe.Info, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	info := new(ifaceprobe.Info)
	if err := dec.Decode(info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interfaces.json: %w", err)
	}
	return info, nil
}

func errorHandler() (func(pos ast.Pos, msg string), *bytes.Buffer) {
	errors := new(bytes.Buffer)
	eh := func(pos ast.Pos, msg string) {
		pos.File = filepath.Base(pos.File)
		fmt.Fprintf(errors, "%v: %v\n", pos, msg)
	}
	return eh, errors
}

func serialize(interfaces []*declextract.Interface) []byte {
	w := new(bytes.Buffer)
	for _, iface := range interfaces {
		fmt.Fprintf(w, "%v\t%v\tfunc:%v\tloc:%v\tcoverage:%v\taccess:%v\tmanual_desc:%v\tauto_desc:%v",
			iface.Type, iface.Name, iface.Func, iface.ReachableLOC,
			cover.Percent(iface.CoveredBlocks, iface.TotalBlocks),
			iface.Access, iface.ManualDescriptions, iface.AutoDescriptions)
		for _, file := range iface.Files {
			fmt.Fprintf(w, "\tfile:%v", file)
		}
		for _, subsys := range iface.Subsystems {
			fmt.Fprintf(w, "\tsubsystem:%v", subsys)
		}
		fmt.Fprintf(w, "\n")
	}
	return w.Bytes()
}

func finishInterfaces(interfaces []*declextract.Interface, consts map[string]*compiler.ConstInfo, autoFile string) {
	manual := make(map[string]bool)
	for file, desc := range consts {
		for _, c := range desc.Consts {
			if file != autoFile {
				manual[c.Name] = true
			}
		}
	}
	extractor := subsystem.MakeExtractor(subsystem.GetList(target.OS))
	for _, iface := range interfaces {
		if iface.IdentifyingConst != "" {
			iface.ManualDescriptions = declextract.Tristate(manual[iface.IdentifyingConst])
		}
		var crashes []*subsystem.Crash
		for _, file := range iface.Files {
			crashes = append(crashes, &subsystem.Crash{GuiltyPath: file})
		}
		for _, s := range extractor.Extract(crashes) {
			iface.Subsystems = append(iface.Subsystems, s.Name)
		}
		slices.Sort(iface.Subsystems)
	}
}

func buildSyscallRenameMap(sourceDir string, arches []string) (map[string][]string, error) {
	// Some syscalls have different names and entry points and thus need to be renamed.
	// e.g. SYSCALL_DEFINE1(setuid16, old_uid_t, uid) is referred to in the .tbl file with setuid.
	// Parse *.tbl files that map functions defined with SYSCALL_DEFINE macros to actual syscall names.
	// Lines in the files look as follows:
	//	288      common  accept4                 sys_accept4
	// Total mapping is many-to-many, so we give preference to x86 arch, then to 64-bit syscalls,
	// and then just order arches by name to have deterministic result.
	// Note: some syscalls may have no record in the tables for the architectures we support.
	syscalls := make(map[string][]tblSyscall)
	tblFiles, err := findTblFiles(sourceDir, arches)
	if err != nil {
		return nil, err
	}
	if len(tblFiles) == 0 {
		return nil, fmt.Errorf("found no *.tbl files in the kernel dir %v", sourceDir)
	}
	for file, arches := range tblFiles {
		for _, arch := range arches {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			parseTblFile(data, arch, syscalls)
		}
	}
	rename := make(map[string][]string)
	for syscall, descs := range syscalls {
		slices.SortFunc(descs, func(a, b tblSyscall) int {
			if (a.arch == target.Arch) != (b.arch == target.Arch) {
				if a.arch == target.Arch {
					return -1
				}
				return 1
			}
			if a.is64bit != b.is64bit {
				if a.is64bit {
					return -1
				}
				return 1
			}
			return strings.Compare(a.arch, b.arch)
		})
		fn := descs[0].fn
		rename[fn] = append(rename[fn], syscall)
	}
	return rename, nil
}

type tblSyscall struct {
	fn      string
	arch    string
	is64bit bool
}

func parseTblFile(data []byte, arch string, syscalls map[string][]tblSyscall) {
	for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 || fields[0] == "#" {
			continue
		}
		group := fields[1]
		syscall := fields[2]
		fn := strings.TrimPrefix(fields[3], "sys_")
		if strings.HasPrefix(syscall, "unused") || fn == "-" ||
			// Powerpc spu group defines some syscalls (utimesat)
			// that are not present on any of our arches.
			group == "spu" ||
			// llseek does not exist, it comes from:
			//	arch/arm64/tools/syscall_64.tbl -> scripts/syscall.tbl
			//	62  32      llseek                          sys_llseek
			// So scripts/syscall.tbl is pulled for 64-bit arch, but the syscall
			// is defined only for 32-bit arch in that file.
			syscall == "llseek" ||
			// Don't want to test it (but see issue 5308).
			syscall == "reboot" {
			continue
		}
		syscalls[syscall] = append(syscalls[syscall], tblSyscall{
			fn:      fn,
			arch:    arch,
			is64bit: group == "common" || strings.Contains(group, "64"),
		})
	}
}

func findTblFiles(sourceDir string, arches []string) (map[string][]string, error) {
	files := make(map[string][]string)
	for _, name := range arches {
		arch := targets.List[target.OS][name]
		err := filepath.WalkDir(filepath.Join(sourceDir, "arch", arch.KernelHeaderArch),
			func(file string, d fs.DirEntry, err error) error {
				if err == nil && strings.HasSuffix(file, ".tbl") {
					files[file] = append(files[file], arch.VMArch)
				}
				return err
			})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
