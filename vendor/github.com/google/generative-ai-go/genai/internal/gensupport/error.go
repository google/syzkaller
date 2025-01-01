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

package gensupport

import (
	"errors"

	"github.com/googleapis/gax-go/v2/apierror"
	"google.golang.org/api/googleapi"
)

// WrapError creates an [apierror.APIError] from err, wraps it in err, and
// returns err. If err is not a [googleapi.Error] (or a
// [google.golang.org/grpc/status.Status]), it returns err without modification.
func WrapError(err error) error {
	var herr *googleapi.Error
	apiError, ok := apierror.ParseError(err, false)
	if ok && errors.As(err, &herr) {
		herr.Wrap(apiError)
	}
	return err
}
