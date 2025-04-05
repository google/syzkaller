// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-gemini-seed generates program seeds based on existing programs in the corpus using Gemini API.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"runtime"

	"github.com/google/generative-ai-go/genai"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"google.golang.org/api/option"
)

func main() {
	var (
		flagOS     = flag.String("os", runtime.GOOS, "target OS")
		flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
		flagCorpus = flag.String("corpus", "", "wxisting corpus.db file to use as examples")
		flagCount  = flag.Int("count", 1, "number of programs to generate")
		flagAPIKey = flag.String("key", "", "gemini API key to use")
	)
	tool.Init()

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Failf("failed to find target: %v", err)
	}

	db, err := db.Open(*flagCorpus, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(*flagAPIKey))
	if err != nil {
		tool.Fail(err)
	}
	defer client.Close()

	for i := 0; i < *flagCount; i++ {
		model := client.GenerativeModel("gemini-1.5-pro")
		model.SetTemperature(0.9)
		// This does not work (fails with "Only one candidate can be specified").
		// model.SetCandidateCount(3)
		// TODO: tune TopP/TopK.
		// model.SetTopP(0.5)
		// model.SetTopK(20)
		// TODO: do we need any system instructions?
		// model.SystemInstruction = &genai.Content{
		//	Parts: []genai.Part{genai.Text("You are Yoda from Star Wars.")},
		// }

		// In some cases it thinks it generates unsafe content, so disable safety.
		// TODO: this fails with some cryptic error.
		if false {
			for cat := genai.HarmCategoryDerogatory; cat <= genai.HarmCategoryDangerousContent; cat++ {
				model.SafetySettings = append(model.SafetySettings, &genai.SafetySetting{
					Category:  cat,
					Threshold: genai.HarmBlockNone,
				})
			}
		}

		prompt := new(bytes.Buffer)
		prompt.WriteString("Below are examples of test programs in a special notation.\n\n")
		// TODO: select a subset of related programs (using the same syscall).
		n := 0
		for _, rec := range db.Records {
			prompt.WriteString("\n\nHere is an example:\n\n")
			prompt.Write(rec.Val)
			n++
			if len(prompt.Bytes()) > 50<<10 || n >= 20 {
				break
			}
		}
		prompt.WriteString("\n\nPlease generate a similar but different test program with 5 lines.\n")
		prompt.WriteString("Output just the program.\n")
		resp, err := model.GenerateContent(ctx, genai.Text(prompt.String()))
		if err != nil {
			tool.Fail(err)
		}

		for _, cand := range resp.Candidates {
			reply := new(bytes.Buffer)
			if cand.Content != nil {
				for _, part := range cand.Content.Parts {
					if text, ok := part.(genai.Text); ok {
						reply.WriteString(string(text))
					}
				}
			}
			fmt.Printf("REPLY:\n%s\n\n", reply)
			p, err := target.Deserialize(reply.Bytes(), prog.NonStrict)
			if err != nil {
				fmt.Printf("failed to parse: %v\n\n", err)
			} else {
				fmt.Printf("PARSED:\n%s\n\n", p.Serialize())
			}
		}
	}
}
