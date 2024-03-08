package main

import (
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	proglib "github.com/google/syzkaller/prog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const OldCorpusPath = "./syz-manager/data/"
const TokensFilePath = "./syz-manager/data/tokens/tokens_"
const TokenFileSize = 256
const VocabFilePath = "./syz-manager/data/vocab/vocab.txt"

func PreprocessAllCorpora(manager *Manager) {
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
			newLogCollector := NewPreprocessor(manager, corpusDB).Preprocessing()
			logCollector.MergeCnt(newLogCollector)
		}
		return nil
	})

	if err != nil {
		fmt.Println("filepath.Walk Error:", err)
	}
	log.Fatalf("preprocessing exit!\n"+
		"programs cnt: %v \n"+"calls cnt: %v \n"+"replaced args cnt: %v \n"+"panic cnt: %v \n", logCollector.TotalProgramsCnt, logCollector.TotalCallsCnt, logCollector.TotalReplacedArgsCnt, logCollector.TotalPanicCnt)
}

type Preprocessor struct {
	corpusDB     *db.DB
	mgr          *Manager
	argTable     map[string][][]proglib.Arg
	logCollector *LogCollector
}

func NewPreprocessor(manager *Manager, corpusDB *db.DB) *Preprocessor {
	preprocessor := new(Preprocessor)
	preprocessor.corpusDB = corpusDB
	preprocessor.mgr = manager
	preprocessor.argTable = make(map[string][][]proglib.Arg)
	preprocessor.logCollector = NewLogCollector()
	return preprocessor
}

func (preprocessor *Preprocessor) Preprocessing() *LogCollector {
	//preprocessor.InitArgTable()
	preprocessor.ReplaceArgs()
	preprocessor.ParseCorpusToFile()
	log.Logf(0, "preprocessing done! Replaced Args Count: %v, Panic Count: %v", preprocessor.logCollector.TotalReplacedArgsCnt, preprocessor.logCollector.TotalPanicCnt)
	return preprocessor.logCollector
}

func (preprocessor *Preprocessor) InitArgTable() {
	for _, rec := range preprocessor.corpusDB.Records {
		program, err := preprocessor.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			if program == nil {
				continue
			}
			log.Fatalf("InitArgTable - Preprocessor Deserialize record failed: %v", err)
		}

		for _, call := range program.Calls {
			for j, arg := range call.Args {
				preprocessor.InsertArg(call.Meta.Name, j, arg, len(call.Args))
			}
		}
	}
}

func (preprocessor *Preprocessor) InsertArg(callName string, idx int, arg proglib.Arg, callArgSize int) {
	argList, exist := preprocessor.argTable[callName]
	if !exist {
		argList = make([][]proglib.Arg, callArgSize)
	}

	switch arg := arg.(type) {
	case *proglib.DataArg, *proglib.PointerArg, *proglib.GroupArg:
		if len(argList[idx]) < 10 && !ArgContainResArg(arg) {
			argList[idx] = append(argList[idx], arg)
		}
	default:
	}
	preprocessor.argTable[callName] = argList
}

func (preprocessor *Preprocessor) ReplaceArgs() {
	for x, rec := range preprocessor.corpusDB.Records {
		program, err := preprocessor.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			if program == nil {
				continue
			}
			log.Fatalf("ReplaceArgs - Preprocessor Deserialize record failed: %v", err)
		}

		for i, call := range program.Calls {
			preprocessor.logCollector.TotalCallsCnt += 1
			for j, _arg := range call.Args {
				switch arg := _arg.(type) {
				case *proglib.DataArg, *proglib.PointerArg, *proglib.GroupArg:
					program.Calls[i].Args[j] = preprocessor.SearchForArg(call.Meta.Name, j, arg, len(call.Args))
				default:
				}
			}
		}
		//log.Logf(0, "arg cnt: %v", preprocessor.replacedArgsCnt)

		newRecord := preprocessor.MakeRecord(program, rec)
		preprocessor.corpusDB.Records[x] = newRecord
	}
}

func (preprocessor *Preprocessor) MakeRecord(program *proglib.Prog, rec db.Record) db.Record {
	defer func() {
		if r := recover(); r != nil {
			preprocessor.logCollector.TotalPanicCnt += 1
		}
	}()
	newRecord := db.Record{
		Val: program.Serialize(),
		Seq: rec.Seq,
	}
	return newRecord
}

func (preprocessor *Preprocessor) SearchForArg(callName string, idx int, arg proglib.Arg, callArgSize int) proglib.Arg {
	argTableInstance := GetArgTableInstance()
	argList, exist := argTableInstance.argTable[callName]
	if !exist {
		argList = make([][]proglib.Arg, callArgSize)
		//log.Fatalf("Arg: %v has not been collected, callName: %v", arg, callName)
	}

	if len(argList[idx]) <= 0 && !ArgContainResArg(arg) {
		argList[idx] = append(argList[idx], arg)
		argTableInstance.argTable[callName] = argList
		return arg
	}

	if len(argList) > idx && len(argList[idx]) > 0 && arg.Size() == argList[idx][0].Size() && callArgSize == len(argList) {
		preprocessor.logCollector.TotalReplacedArgsCnt += 1
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

func (preprocessor *Preprocessor) ParseCorpusToFile() {
	CreatePathIfNotExist("./syz-manager/data/tokens/")
	CreatePathIfNotExist("./syz-manager/data/vocab/")
	buffer := ""
	fileCount := 1
	programCount := 0
	for _, rec := range preprocessor.corpusDB.Records {
		buffer += string(rec.Val[:]) + "[SEP]\n"
		programCount += 1
		preprocessor.logCollector.TotalProgramsCnt += 1

		if programCount >= TokenFileSize {
			//SaveTokensFile(fileCount, &buffer)
			SaveVocabFile(&buffer)

			fileCount += 1
			programCount = 0
			buffer = ""
		}
	}
	buffer += "[UNK]\n"
	buffer += "[MASK]\n"
	buffer += "[CLS]\n"
	buffer += "[PAD]\n"
	//SaveTokensFile(fileCount, &buffer)
	SaveVocabFile(&buffer)

	log.Logf(0, "total number of sequences (traces): %v", preprocessor.logCollector.TotalProgramsCnt)
}

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

func SaveTokensFile(fileCount int, content *string) {
	f, err := os.Create(TokensFilePath + strconv.Itoa(fileCount) + ".txt")
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

var argTableInstance *ArgTable
var once sync.Once

// GetInstance returns the singleton instance
func GetArgTableInstance() *ArgTable {
	once.Do(func() {
		argTableInstance = &ArgTable{argTable: make(map[string][][]proglib.Arg)}
	})
	return argTableInstance
}

type LogCollector struct {
	TotalProgramsCnt     int
	TotalCallsCnt        int
	TotalReplacedArgsCnt int
	TotalPanicCnt        int
}

func NewLogCollector() *LogCollector {
	logCollector := new(LogCollector)
	logCollector.TotalProgramsCnt = 0
	logCollector.TotalCallsCnt = 0
	logCollector.TotalReplacedArgsCnt = 0
	logCollector.TotalPanicCnt = 0

	return logCollector
}

func (logCollector *LogCollector) MergeCnt(newLogCollector *LogCollector) {
	logCollector.TotalProgramsCnt += newLogCollector.TotalProgramsCnt
	logCollector.TotalCallsCnt += newLogCollector.TotalCallsCnt
	logCollector.TotalReplacedArgsCnt += newLogCollector.TotalReplacedArgsCnt
	logCollector.TotalPanicCnt += newLogCollector.TotalPanicCnt
}
