package main

import (
	"fmt"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	proglib "github.com/google/syzkaller/prog"
	"os"
	"strconv"
)

const OldCorpusPath = "./data/corpus.db"
const TokensFilePath = ".data/tokens/tokens_"
const TokenFileSize = 256
const VocabFilePath = ".data/vocab/vocab.txt"

type Preprocessor struct {
	corpusDB *db.DB
	mgr      *Manager
	argTable map[string][][]proglib.Arg
}

func NewPreprocessor(manager *Manager) *Preprocessor {
	corpusDB, err := db.Open(OldCorpusPath, true)
	if err != nil {
		if corpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Errorf("read %v inputs from corpus and got error: %v", len(corpusDB.Records), err)
	}

	preprocessor := new(Preprocessor)
	preprocessor.corpusDB = corpusDB
	preprocessor.mgr = manager
	return preprocessor
}

func (preprocessor *Preprocessor) Preprocessing() {
	preprocessor.InitArgTable()
	preprocessor.ReplaceArgs()
	preprocessor.ParseCorpusToFile()
}

func (preprocessor *Preprocessor) InitArgTable() {
	for _, rec := range preprocessor.corpusDB.Records {
		program, err := preprocessor.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			log.Fatalf("Preprocessor Deserialize record failed: %v", err)
		}

		for _, call := range program.Calls {
			for j, arg := range call.Args {
				preprocessor.InsertArg(call.Meta.Name, j, arg, len(call.Args))
			}
		}
	}
}

func (preprocessor *Preprocessor) ReplaceArgs() {
	for _, rec := range preprocessor.corpusDB.Records {
		program, err := preprocessor.mgr.target.Deserialize(rec.Val[:], proglib.NonStrict)
		if err != nil {
			log.Fatalf("Preprocessor Deserialize record failed: %v", err)
		}

		for i, call := range program.Calls {
			for j, arg := range call.Args {
				switch arg := arg.(type) {
				case *proglib.DataArg:
					call.Args[j] = preprocessor.ReplaceBufferArg(arg)
				default:
				}
			}
			program.Calls[i] = call
		}
	}
}

func (preprocessor *Preprocessor) ReplaceBufferArg(dataArg *proglib.DataArg) *proglib.DataArg {
	return nil
}

func (preprocessor *Preprocessor) InsertArg(callName string, idx int, arg proglib.Arg, callArgSize int) {
	argList, exist := preprocessor.argTable[callName]
	if !exist {
		argList = make([][]proglib.Arg, callArgSize)
	}

	switch arg := arg.(type) {
	case *proglib.DataArg, *proglib.PointerArg, *proglib.GroupArg:
		argList[idx] = append(argList[idx], arg)
	default:
	}
	preprocessor.argTable[callName] = argList
}

func (preprocessor *Preprocessor) ParseCorpusToFile() {
	CreatePathIfNotExist("./tokens/")
	CreatePathIfNotExist("./vocab/")
	buffer := ""
	fileCount := 1
	sequenceCount := 0
	totalCount := 0
	for _, rec := range preprocessor.corpusDB.Records {
		buffer += string(rec.Val[:]) + "[SEP]\n"
		sequenceCount += 1
		totalCount += 1

		if sequenceCount >= TokenFileSize {
			SaveTokensFile(fileCount, &buffer)
			SaveVocabFile(&buffer)

			fileCount += 1
			sequenceCount = 0
			buffer = ""
		}
	}
	buffer += "[UNK]\n"
	buffer += "[MASK]\n"
	buffer += "[CLS]\n"
	buffer += "[PAD]\n"
	SaveTokensFile(fileCount, &buffer)
	SaveVocabFile(&buffer)

	log.Logf(0, "total number of sequences (traces): %v", totalCount)
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
