// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package defs provides constants required by go-fuzz-build, go-fuzz, and instrumented code.
package base

// This package has a special interaction with go-fuzz-dep:
// It is copied into a package with it by go-fuzz-build.
// Only things that can be safely duplicated without confusion,
// like constants, should be added to this package.
// And any additions should be tested carefully. :)

const (
	CoverSize       = 64 << 10
	MaxInputSize    = 1 << 20
	SonarRegionSize = 1 << 20
)

const (
	SonarEQL = iota
	SonarNEQ
	SonarLSS
	SonarGTR
	SonarLEQ
	SonarGEQ

	SonarOpMask = 7
	SonarLength = 1 << 3
	SonarSigned = 1 << 4
	SonarString = 1 << 5
	SonarConst1 = 1 << 6
	SonarConst2 = 1 << 7

	SonarHdrLen = 6
	SonarMaxLen = 20
)
