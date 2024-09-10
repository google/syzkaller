// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains debugging support functions.

package genai

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// printRequests controls whether request protobufs are written to stderr.
var printRequests = false

func debugPrint(m proto.Message) {
	if !printRequests {
		return
	}
	fmt.Fprintln(os.Stderr, "--------")
	fmt.Fprintf(os.Stderr, "%T\n", m)
	fmt.Fprint(os.Stderr, prototext.Format(m))
	fmt.Fprintln(os.Stderr, "^^^^^^^^")
}
