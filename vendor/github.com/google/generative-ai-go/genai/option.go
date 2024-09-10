// Copyright 2024 Google LLC
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

package genai

import (
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
)

// WithClientInfo sets request information identifying the
// product that is calling this client.
func WithClientInfo(key, value string) option.ClientOption {
	return &clientInfo{key: key, value: value}
}

type clientInfo struct {
	internaloption.EmbeddableAdapter
	key, value string
}

// optionOfType returns the first value of opts that has type T,
// along with true. If there is no option of that type, it returns
// the zero value for T and false.
func optionOfType[T option.ClientOption](opts []option.ClientOption) (T, bool) {
	for _, opt := range opts {
		if opt, ok := opt.(T); ok {
			return opt, true
		}
	}
	var z T
	return z, false
}
