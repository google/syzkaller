// Copyright 2020 Google LLC
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

//go:build gofuzz
// +build gofuzz

package spansql

func FuzzParseQuery(data []byte) int {
	if _, err := ParseQuery(string(data)); err != nil {
		// The value 0 signals data is an invalid query that should be
		// added to the corpus.
		return 0
	}
	// The value 1 signals the input was lexically corrent and the
	// fuzzer should increase the priority of the given input.
	return 1
}
