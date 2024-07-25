package main

import (
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	proglib "github.com/google/syzkaller/prog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const OldCorpusPath = "./syz-manager/data/"
const TokensFilePath = "./syz-manager/data/tokens/tokens_"
const TokenFileSize = 256
const VocabFilePath = "./syz-manager/data/vocab/vocab.txt"

func PreprocessAllCorpora(manager *Manager, preprocessorType PreprocessorType) {
	logCollector := NewLogCollector()
	// Walk through the directory
	err := filepath.Walk(OldCorpusPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file is a corpus
		if !info.IsDir() && strings.Contains(path, "corpus") {
			corpusDB, err := db.Open(path, true)
			if err != nil {
				if corpusDB == nil {
					log.Fatalf("failed to open corpus database: %v", err)
				}
				log.Errorf("read %v inputs from corpus and got error: %v", len(corpusDB.Records), err)
			}
			newLogCollector := NewPreprocessor(manager, corpusDB, preprocessorType).Preprocessing()
			logCollector.MergeCnt(newLogCollector)
		}
		return nil
	})

	if preprocessorType == AllocateConstant {
		SaveAddr()
	}

	if err != nil {
		fmt.Println("filepath.Walk Error:", err)
	}
	log.Fatalf("preprocessing exit!\n"+
		"programs cnt: %v \n"+"calls cnt: %v \n"+"replaced args cnt: %v \n"+"panic cnt: %v \n"+"max sequence length: %v \n"+"broken progs: %v\n"+"Any: %v\n", logCollector.TotalProgramsCnt, logCollector.TotalCallsCnt, logCollector.TotalReplacedArgsCnt, logCollector.TotalPanicCnt, logCollector.MaxProgramLength, logCollector.BrokenProgCNT, logCollector.Cnt)
}

type Preprocessor interface {
	Preprocessing() *LogCollector
}

type PreprocessorBase struct {
	corpusDB        *db.DB
	recordsCopy     map[string]db.Record // filter broken programs
	mgr             *Manager
	logCollector    *LogCollector
	currentCallName string
	currentProg     string
}

func (p *PreprocessorBase) ParseCorpusToFile() {
	CreatePathIfNotExist("./syz-manager/data/tokens/")
	CreatePathIfNotExist("./syz-manager/data/vocab/")
	buffer := ""
	programCount := 0
	for _, rec := range p.corpusDB.Records {
		if IsDuplication(string(rec.Val[:])) {
			continue
		}
		//buffer += string(rec.Val[:]) + "[SEP]\n"
		buffer += ConvertResource(rec.Val[:]) + "[SEP]\n"
		programCount += 1
		p.logCollector.TotalProgramsCnt += 1

		if programCount >= TokenFileSize {
			buffer = ConvertAnyBlob(buffer)
			SaveTokensFile(&buffer)
			SaveVocabFile(&buffer)

			tokenFileCnt += 1
			programCount = 0
			buffer = ""
		}
	}
	buffer += "[UNK]\n"
	buffer += "[MASK]\n"
	buffer += "[CLS]\n"
	buffer += "[PAD]\n"
	buffer = ConvertAnyBlob(buffer)
	SaveTokensFile(&buffer)
	SaveVocabFile(&buffer)

	log.Logf(0, "total number of sequences (traces): %v", p.logCollector.TotalProgramsCnt)
}

func (p *PreprocessorBase) MakeRecord(program *proglib.Prog, rec db.Record) db.Record {
	defer func() {
		if r := recover(); r != nil {
			p.logCollector.TotalPanicCnt += 1
		}
	}()
	newRecord := db.Record{
		Val: program.Serialize(),
		Seq: rec.Seq,
	}
	return newRecord
}

func NewPreprocessor(manager *Manager, corpusDB *db.DB, preprocessorType PreprocessorType) Preprocessor {
	pBase := new(PreprocessorBase)
	pBase.corpusDB = corpusDB
	pBase.recordsCopy = make(map[string]db.Record)
	for k, v := range corpusDB.Records {
		pBase.recordsCopy[k] = v
	}
	pBase.mgr = manager
	pBase.logCollector = NewLogCollector()

	switch preprocessorType {
	case AllocateConstant:
		return &PAllocateConstant{pBase}
	case Brutal:
		return &PBrutal{pBase}
	default:
		return &PAllocateConstant{pBase}
	}
}

type PreprocessorType int

const (
	AllocateConstant PreprocessorType = iota
	Brutal
)

type PAllocateConstant struct {
	*PreprocessorBase
}

func (p *PAllocateConstant) Preprocessing() *LogCollector {
	//preprocessor.ReplaceArgs()
	p.Replace()
	p.ParseCorpusToFile()
	log.Logf(0, "preprocessing done! Replaced Args Count: %v, Panic Count: %v", p.logCollector.TotalReplacedArgsCnt, p.logCollector.TotalPanicCnt)
	return p.logCollector
}

func (p *PAllocateConstant) Replace() {
	for x, rec := range p.corpusDB.Records {
		program, err := p.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			if program == nil {
				//log.Logf(0, "prog:\n %v\n", string(rec.Val[:]))
				p.logCollector.BrokenProgCNT += 1
				p.logCollector.TotalPanicCnt += len(ParseCallsText(rec.Val[:]))
				delete(p.recordsCopy, x)
				continue
			}
			log.Fatalf("ReplaceArgs - Preprocessor Deserialize record failed: %v", err)
		}
	}
	p.corpusDB.Records = p.recordsCopy

	for x, rec := range p.corpusDB.Records {
		program, err := p.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			if program == nil {
				log.Fatalf("prog:\n %v\n", string(rec.Val[:]))
				continue
			}
			log.Fatalf("ReplaceArgs - Preprocessor Deserialize record failed: %v", err)
		}
		p.logCollector.CalcMaxProgramLength(len(program.Calls))
		p.currentProg = string(rec.Val[:])

		GetAddrGeneratorInstance().ResetCounter()

		for i, call := range program.Calls {
			p.logCollector.TotalCallsCnt += 1
			//GetAddrGeneratorInstance().ResetCounter()
			fields := call.Meta.Args
			for j, _arg := range call.Args {
				switch arg := _arg.(type) {
				case *proglib.ResultArg:
					continue
				default:
					p.currentCallName = call.Meta.Name
					program.Calls[i].Args[j] = p.DFSArgs(arg, fields[j])
				}
			}
		}
		//log.Logf(0, "arg cnt: %v", preprocessor.replacedArgsCnt)

		newRecord := p.MakeRecord(program, rec)
		p.corpusDB.Records[x] = newRecord
	}
}

func (p *PAllocateConstant) DFSArgs(arg proglib.Arg, field proglib.Field) proglib.Arg {
	switch argType := arg.(type) {
	case *proglib.DataArg:
		return p.GenerateDataArg(argType, field.Type)
	case *proglib.ConstArg:
		return p.GenerateConstArg(argType, field.Type, field.Name)
	case *proglib.UnionArg:
		return p.GenerateUnionArg(argType, field.Type)
	case *proglib.PointerArg:
		return p.GeneratePtrArg(argType, field.Type)
	case *proglib.GroupArg:
		return p.GenerateGroupArg(argType, field.Type)
	default:
		return arg
	}
}

// GenerateDataArg todo: buffer addr generator, identify path
// some of buffer values are choose from BufferType.Values, seems a type of flags
func (p *PAllocateConstant) GenerateDataArg(dataArg *proglib.DataArg, fieldType proglib.Type) proglib.Arg {
	const Path = "./file0\x00"
	const BufferSize = 0x400
	data := make([]byte, 0)

	if dataArg.ArgCommon.Dir() == proglib.DirOut {
		return proglib.MakeOutDataArg(dataArg.ArgCommon.Type(), dataArg.ArgCommon.Dir(), BufferSize)
	} else if dataArg.ArgCommon.Dir() == proglib.DirIn {
		switch ft := fieldType.(type) {
		case *proglib.BufferType:
			if ft.Kind == proglib.BufferFilename {
				data = []byte(Path)
			} else if len(ft.Values) > 0 {
				data = []byte(ft.Values[0])
			} else {
				data = make([]byte, BufferSize)
				for i := 0; i < BufferSize; i++ {
					data[i] = 0
				}
			}
		}
		return proglib.MakeDataArg(dataArg.ArgCommon.Type(), dataArg.ArgCommon.Dir(), data)
	}

	return dataArg
}

// GenerateConstArg some of const values are choose from UnionType.Fields by ConstArg.Index, seems a type of flags
func (p *PAllocateConstant) GenerateConstArg(constArg *proglib.ConstArg, fieldType proglib.Type, fieldName string) proglib.Arg {
	const FD = ^uint64(0)
	const NUM = 0x111

	switch fieldType.(type) {
	case *proglib.FlagsType:
		return constArg
	default:
		if fieldName == "mode" {
			return constArg
		} else if fieldName == "fd" {
			return proglib.MakeConstArg(constArg.ArgCommon.Type(), constArg.ArgCommon.Dir(), FD)
		} else {
			return proglib.MakeConstArg(constArg.ArgCommon.Type(), constArg.ArgCommon.Dir(), NUM)
		}
	}
}

func (p *PAllocateConstant) GenerateUnionArg(unionArg *proglib.UnionArg, fieldType proglib.Type) proglib.Arg {
	switch ft := fieldType.(type) {
	case *proglib.UnionType:
		switch argOption := unionArg.Option.(type) {
		case *proglib.DataArg:
			unionArg.Option = p.GenerateDataArg(argOption, ft.Fields[unionArg.Index].Type)
		case *proglib.ConstArg:
			unionArg.Option = p.GenerateConstArg(argOption, ft.Fields[unionArg.Index].Type, ft.Fields[unionArg.Index].Name)
		case *proglib.PointerArg:
			unionArg.Option = p.GeneratePtrArg(argOption, ft.Fields[unionArg.Index].Type)
		case *proglib.GroupArg:
			unionArg.Option = p.GenerateGroupArg(argOption, ft.Fields[unionArg.Index].Type)
		case *proglib.UnionArg:
			unionArg.Option = p.GenerateUnionArg(argOption, ft.Fields[unionArg.Index].Type)
		}
	}

	return unionArg
}

func (p *PAllocateConstant) GenerateGroupArg(groupArg *proglib.GroupArg, fieldType proglib.Type) proglib.Arg {
	switch ft := fieldType.(type) {
	case *proglib.StructType:
		if len(groupArg.Inner) != len(ft.Fields) {
			break
		}

		for i, child := range groupArg.Inner {
			switch child := child.(type) {
			case *proglib.DataArg:
				groupArg.Inner[i] = p.GenerateDataArg(child, ft.Fields[i].Type)
			case *proglib.ConstArg:
				groupArg.Inner[i] = p.GenerateConstArg(child, ft.Fields[i].Type, ft.Fields[i].Name)
			case *proglib.GroupArg:
				groupArg.Inner[i] = p.GenerateGroupArg(child, ft.Fields[i].Type)
			case *proglib.PointerArg:
				groupArg.Inner[i] = p.GeneratePtrArg(child, ft.Fields[i].Type)
			case *proglib.UnionArg:
				groupArg.Inner[i] = p.GenerateUnionArg(child, ft.Fields[i].Type)
			}
		}
	}

	return groupArg
}

func (p *PAllocateConstant) GeneratePtrArg(ptrArg *proglib.PointerArg, fieldType proglib.Type) proglib.Arg {
	ptrArg.Address = GetAddr(p.currentCallName)

	switch ft := fieldType.(type) {
	case *proglib.PtrType:
		switch ptrRes := ptrArg.Res.(type) {
		case *proglib.DataArg:
			ptrArg.Res = p.GenerateDataArg(ptrRes, ft.Elem)
		case *proglib.ConstArg:
			ptrArg.Res = p.GenerateConstArg(ptrRes, ft.Elem, "")
		case *proglib.GroupArg:
			ptrArg.Res = p.GenerateGroupArg(ptrRes, ft.Elem)
		case *proglib.UnionArg:
			ptrArg.Res = p.GenerateUnionArg(ptrRes, ft.Elem)
		case *proglib.PointerArg:
			ptrArg.Res = p.GeneratePtrArg(ptrRes, ft.Elem)
		}
	}

	return ptrArg
}

var _addrGeneratorInstance *AddrGenerator
var _addrGeneratorOnce sync.Once

func GetAddrGeneratorInstance() *AddrGenerator {
	_addrGeneratorOnce.Do(func() {
		_addrGeneratorInstance = &AddrGenerator{addrCounter: make(map[string]uint64), addrBase: make(map[string]uint64)}
	})
	return _addrGeneratorInstance
}

type AddrGenerator struct {
	addrCounter map[string]uint64
	addrBase    map[string]uint64
}

const BaseAddr = uint64(0x0)
const AddrSameCallStep = uint64(0x400)
const AddrDiffCallStep = AddrSameCallStep * 4

// GetAddr todo:
// check two strategies, current is 2:
// 1. for all the addrs in each program, mapping them to symbols in order
// 2. for addrs in each call, mapping...
func GetAddr(callName string) uint64 {
	addrGenerator := GetAddrGeneratorInstance()
	cnt, ok := addrGenerator.addrCounter[callName]
	if !ok {
		addrGenerator.addrCounter[callName] = 0
		addrGenerator.addrBase[callName] = BaseAddr + AddrDiffCallStep*uint64(len(addrGenerator.addrCounter))
		cnt = addrGenerator.addrCounter[callName]
	}
	addrGenerator.addrCounter[callName] += 1

	return addrGenerator.addrBase[callName] + AddrSameCallStep*cnt
}

func (a *AddrGenerator) ResetCounter() {
	for key := range a.addrCounter {
		a.addrCounter[key] = 0
	}
}

func SaveAddr() {
	const AddrPath = "./syz-manager/data/addr.txt"
	file, err := os.Create(AddrPath)
	if err != nil {
		fmt.Println("Error creating addr.txt:", err)
		return
	}
	defer file.Close()

	cnt := 0
	addrGenerator := GetAddrGeneratorInstance()
	for key, value := range addrGenerator.addrBase {
		cnt += 1
		line := fmt.Sprintf("%s %d\n", key, value)
		_, err := file.WriteString(line)
		if err != nil {
			fmt.Println("Error writing to addr.txt:", err)
			return
		}
	}

	log.Logf(0, "addr.txt saved %v", cnt)
}

func ParseCallsText(prog []byte) []string {
	calls := strings.Split(string(prog[:]), "\n")
	callsCopy := make([]string, len(calls))
	copy(callsCopy[:], calls[:])
	removeCNT := 0
	for i, call := range calls {
		if len(call) <= 0 || call[0] == '#' {
			callsCopy = Remove(callsCopy, i-removeCNT)
			removeCNT += 1
		}
	}
	return callsCopy
}

func Remove(slice []string, index int) []string {
	return append(slice[:index], slice[index+1:]...)
}

type PBrutal struct {
	*PreprocessorBase
}

func (p *PBrutal) Preprocessing() *LogCollector {
	//preprocessor.ReplaceArgs()
	p.Replace()
	p.ParseCorpusToFile()
	log.Logf(0, "preprocessing done! Replaced Args Count: %v, Panic Count: %v", p.logCollector.TotalReplacedArgsCnt, p.logCollector.TotalPanicCnt)
	return p.logCollector
}

func (p *PBrutal) Replace() {
	for x, rec := range p.corpusDB.Records {
		program, err := p.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			if program == nil {
				continue
			}
			log.Fatalf("ReplaceArgs - Preprocessor Deserialize record failed: %v", err)
		}
		p.logCollector.CalcMaxProgramLength(len(program.Calls))

		for i, call := range program.Calls {
			p.logCollector.TotalCallsCnt += 1
			for j, _arg := range call.Args {
				switch arg := _arg.(type) {
				case *proglib.DataArg, *proglib.PointerArg, *proglib.GroupArg:
					program.Calls[i].Args[j] = p.SearchForArg(call.Meta.Name, j, arg, len(call.Args))
				default:
				}
			}
		}
		//log.Logf(0, "arg cnt: %v", preprocessor.replacedArgsCnt)

		newRecord := p.MakeRecord(program, rec)
		p.corpusDB.Records[x] = newRecord
	}
}

func (p *PBrutal) SearchForArg(callName string, idx int, arg proglib.Arg, callArgSize int) proglib.Arg {
	argTableInstance := GetArgTableInstance()
	argList, exist := argTableInstance.argTable[callName]
	if !exist {
		argList = make([][]proglib.Arg, callArgSize)
		//log.Fatalf("Arg: %v has not been collected, callName: %v", arg, callName)
	}

	// collect arg
	if len(argList[idx]) <= 0 && !ArgContainResArg(arg) {
		argList[idx] = append(argList[idx], arg)
		argTableInstance.argTable[callName] = argList
		return arg
	}

	if len(argList) > idx && len(argList[idx]) > 0 && arg.Size() == argList[idx][0].Size() && callArgSize == len(argList) {
		p.logCollector.TotalReplacedArgsCnt += 1
		return argList[idx][0]
	}
	return arg
}

func ArgContainResArg(arg proglib.Arg) bool {
	switch arg := arg.(type) {
	case *proglib.PointerArg:
		return PtrArgDFSContainResArg(arg)
	case *proglib.GroupArg:
		return GroupArgDFSContainResArg(arg)
	default:
	}
	return false
}

func PtrArgDFSContainResArg(arg *proglib.PointerArg) bool {
	switch argRes := arg.Res.(type) {
	case *proglib.PointerArg:
		return PtrArgDFSContainResArg(argRes)
	case *proglib.GroupArg:
		return GroupArgDFSContainResArg(argRes)
	case *proglib.UnionArg:
		return UnionArgDFSContainResArg(argRes)
	case *proglib.ResultArg:
		return true
	default:
	}
	return false
}

func GroupArgDFSContainResArg(arg *proglib.GroupArg) bool {
	contain := false
	for _, child := range arg.Inner {
		switch child := child.(type) {
		case *proglib.GroupArg:
			contain = contain || GroupArgDFSContainResArg(child)
		case *proglib.PointerArg:
			contain = contain || PtrArgDFSContainResArg(child)
		case *proglib.UnionArg:
			contain = contain || UnionArgDFSContainResArg(child)
		case *proglib.ResultArg:
			return true
		default:
		}
	}
	return contain
}

func UnionArgDFSContainResArg(arg *proglib.UnionArg) bool {
	switch argOption := arg.Option.(type) {
	case *proglib.PointerArg:
		return PtrArgDFSContainResArg(argOption)
	case *proglib.GroupArg:
		return GroupArgDFSContainResArg(argOption)
	case *proglib.UnionArg:
		return UnionArgDFSContainResArg(argOption)
	case *proglib.ResultArg:
		return true
	default:
	}
	return false
}

var tokenFileCnt int = 0

func CreatePathIfNotExist(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			fmt.Println("Failed to create folder:", err)
			return
		}
		fmt.Println("Folder created successfully!")
	} else {
		fmt.Println("Folder already exists!")
	}
}

func SaveTokensFile(content *string) {
	f, err := os.Create(TokensFilePath + strconv.Itoa(tokenFileCnt) + ".txt")
	if err != nil {
		log.Fatalf("open token error :", err)
		return
	}

	_, err = f.Write([]byte(*content))
	if err != nil {
		log.Fatalf("write token error: ", err)
		return
	}

	err = f.Close()
	if err != nil {
		log.Fatalf("Close token error: ", err)
		return
	}
}

func SaveVocabFile(content *string) {
	f, err := os.OpenFile(VocabFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("open token error :", err)
		return
	}

	_, err = f.Write([]byte(*content))
	if err != nil {
		log.Fatalf("write token error: ", err)
		return
	}

	err = f.Close()
	if err != nil {
		log.Fatalf("Close token error: ", err)
		return
	}
}

type ArgTable struct {
	argTable map[string][][]proglib.Arg
}

var _argTableInstance *ArgTable
var argTableOnce sync.Once

// GetInstance returns the singleton instance
func GetArgTableInstance() *ArgTable {
	argTableOnce.Do(func() {
		_argTableInstance = &ArgTable{
			argTable: make(map[string][][]proglib.Arg),
		}
	})
	return _argTableInstance
}

type LogCollector struct {
	TotalProgramsCnt     int
	TotalCallsCnt        int
	TotalReplacedArgsCnt int
	TotalPanicCnt        int
	BrokenProgCNT        int
	MaxProgramLength     int
	Cnt                  int
}

func NewLogCollector() *LogCollector {
	logCollector := new(LogCollector)
	logCollector.TotalProgramsCnt = 0
	logCollector.TotalCallsCnt = 0
	logCollector.TotalReplacedArgsCnt = 0
	logCollector.TotalPanicCnt = 0
	logCollector.BrokenProgCNT = 0
	logCollector.MaxProgramLength = 0
	logCollector.Cnt = 0

	return logCollector
}

func (logCollector *LogCollector) MergeCnt(newLogCollector *LogCollector) {
	logCollector.TotalProgramsCnt += newLogCollector.TotalProgramsCnt
	logCollector.TotalCallsCnt += newLogCollector.TotalCallsCnt
	logCollector.TotalReplacedArgsCnt += newLogCollector.TotalReplacedArgsCnt
	logCollector.TotalPanicCnt += newLogCollector.TotalPanicCnt
	logCollector.BrokenProgCNT += newLogCollector.BrokenProgCNT
	logCollector.Cnt += newLogCollector.Cnt
	logCollector.MaxProgramLength = logCollector.CalcMaxProgramLength(newLogCollector.MaxProgramLength)
}

func (logCollector *LogCollector) CalcMaxProgramLength(length int) int {
	logCollector.MaxProgramLength = max(logCollector.MaxProgramLength, length)
	return logCollector.MaxProgramLength
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ConvertResource(prog []byte, args ...bool) string {
	var repalceWithArgs = false
	if len(args) > 0 {
		repalceWithArgs = args[0]
	}

	calls := ParseCallsText(prog)
	str := string(prog[:])

	for _, call := range calls {
		words := strings.Split(call, " ")
		if len(words) >= 3 && words[0][0] == 'r' && words[1] == "=" {
			res := words[0]
			// todo: replace with no args
			resDef := call[len(words[0])+3 : len(call)]
			if repalceWithArgs {

			}
			resMark := ResPrefix + resDef + ResSuffix
			str = strings.Replace(str, res+",", resMark+",", -1)
			str = strings.Replace(str, res+")", resMark+")", -1)
			str = strings.Replace(str, res+"}", resMark+"}", -1)
		}
	}

	return str
}

func IsDuplication(prog string) bool {
	instance := GetDeduplicatorInstance()
	if instance.ItemExists(prog) {
		return true
	}
	instance.AddItem(prog)
	return false
}

type Deduplicator struct {
	Set map[interface{}]struct{}
}

var (
	_DeduplicatorInstance *Deduplicator
	_DeduplicatorOnce     sync.Once
)

func GetDeduplicatorInstance() *Deduplicator {
	_DeduplicatorOnce.Do(func() {
		_DeduplicatorInstance = &Deduplicator{
			Set: map[interface{}]struct{}{},
		}
	})
	return _DeduplicatorInstance
}

func (d *Deduplicator) AddItem(item interface{}) {
	_, found := d.Set[item]
	if !found {
		d.Set[item] = struct{}{}
	}
}

func (d *Deduplicator) ItemExists(item interface{}) bool {
	_, exists := d.Set[item]
	return exists
}

func (d *Deduplicator) ClearSet() {
	d.Set = make(map[interface{}]struct{})
}

const ResPrefix = "@RSTART@"
const ResSuffix = "@REND@"

func ConvertAnyBlob(s string) string {
	re := regexp.MustCompile(`@ANYBLOB="([a-zA-Z0-9]+)"`)
	return re.ReplaceAllString(s, ANYBLOB)
}

const ANYBLOB = `@ANYBLOB="02000000bf0100000000000000000000ba010000086e000021232948de042774602f36cddb4aa287b3b3312d91f7fbcd26167f6444b666b5023d6da31997c5864183bb5548c8d5210899d6b5b6d5efcd76ffd06e3e62e26c761a6047d17f3aed967ad2b9eaceeae2cb7df923371fd5e88cb2109310447fd0b311245765d6097e53a8c17cc048956f81eae779bb571cacac48a457bd4d0318be01a875d8a9d7039d2c88658fdc197346946806aca29bd51e448d160dee6cb1b7154b67078c77c404f67883fdeea217dddce5faf01620da79e102ffa9192e2b0b89fc559edd377d1ba0dce6baf4f99d80879756b350f508274acd1cd428d448cf820f4706031e75835813e13b954579822cabf5c49c204788c967997833ccbf197ef5fe6a6fa3b8cc8808fb8af13058263c1f576dad05236f15a8d4d9d46f05a2d510e430f553756fd3aae8cba7bac5f2ca2a3eb779f29b0a7fb6cffc073f9c9d76da64ca91814f1a08c83ab9c767b1f24c59ca4e1fe4e501d3e220cf8146fb7c4a4726a97cd02b93c47222218804eebd1795e9a389f75da01498ff1e648773fb5f475018227e3181a51afc21c91c366668868d18242d62acd0c19e46a20d7e2579880633802e262c359e3a2937675d237339e1abeb27f4ae33d12ffeccb69618e6000356b856433cc859be20e7de9b899d21a99a041c7f689f04c2347549df5412ed2a6fc6f5b8d6d16d81e8474d47ea907603135c43f58f8940fe3fecb80e4b03c63159f827ad5aa2c7cd90bde569cd757832446fa385df7c2202b835c30b1d337b42790ba5e9beb9d4d3b8806e2e978b5db841aff85e17cf8d73874f436bc76f336c123a7cf67e3992ae8f0645bb88d41b9437ce7593451437a1be6b7208faafad77d91ea449f7421228b7d8883e072c2abaaf80681038e15b69e0c7f4868f0cd115fd2607f0f5305114595e04359350c6b0580c5311c4dc7f89c86d3184d9fc1f9cc0250968bad83cc9ae7fa8081a6f47ca9eb7b4697b9c70af9277933c3881ff5fbc5a7264038ce11f170c24009d9d3113fa537207baacf105949e4ee99074bc199acd0b9c14fc63e77a6f54f90584779ac5d7e88ac1fbbd09f880d91c25c77570f42a7c1e6e718c40a7591ae419d5ff1cd0362fa4c9fb7ead87ea540ccfe69565abac2a4a3fd7e1090cdba043c3487c291a6d17cdb50e4ec6e7b0c437527cdecf3fe6e03727ecbb1c0284466431d782dd35c306428e3880379de2c4f47301e5d498035abd0b7a92da78aacfbf91a8ce711ab8cbedfbf45f934d31d15668712873041bb7972b65e807912306e736e08fa8570afef98bcd20c5b627dfa990ff78f1381398bfa0594ab42c00234345463df635fc7f4b5eea378497c53205306e27ae120a903570cdf6ff063797c84f78ded9a4e5a8a6dd40e0295a670624bf2c1e81d4b48a6d904b36accc0f09fdc24d1bfc31c84a9a9e10b2d7b11c78bd5945b0ffdc38f4cdec08c53670340cc778c7ac80bf5a36ca4b618f39b66db6f7a9b7d553af0d68ff41e2fcce96d6fd41373ead8b1d827e97cb281e2e78380e5e8e340d392e60f3125eed1295b07726c74aaebfd35fc927de7613a4c967054b78be29fe2f38d78ad4d24b1dea04125bf738e2a46ab415265d75403e9ef7ab2612389d4d"`
