// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package clangtoolimpl

//// Common build flags for all C++ clang tools.
//// We install this file into all tool subdirs as a symbolic link.
//
// #cgo CXXFLAGS: -std=c++23 -O2 -fno-exceptions -I..
// #cgo CXXFLAGS: -Wno-changes-meaning -Wno-deprecated-enum-enum-conversion
//
// #cgo LDFLAGS: -lclangTooling -lclangFrontend -lclangSerialization -lclangDriver
// #cgo LDFLAGS: -lclangToolingCore -lclangParse -lclangSema -lclangAPINotes -lclangAnalysis
// #cgo LDFLAGS: -lclangASTMatchers -lclangRewrite -lclangEdit -lclangAST -lclangLex
// #cgo LDFLAGS: -lclangBasic -lclangSupport -lLLVM
//
//// These flags are distro/version specific.
//// Cgo does not support running shell commands to produce flags.
//// We would need to run:
////   llvm-config --cxxflags
////   llvm-config --ldflags --libs --system-libs
//// There are some work-arounds like exporting CGO_CXXFLAGS/LDLFAGS in the Makefile,
//// or using go generate, but these won't work for bare go test runs.
//// For now, we hardcode typical path the several supported llvm versions.
//// The compiler will search in all of them in order, and pick the first
//// that is actually present and contains files.
//
// #cgo CXXFLAGS: -I/usr/include/llvm-21 -I/usr/lib/llvm-21/include -I/usr/include/llvm-c-21
// #cgo LDFLAGS: -L/usr/lib/llvm-21/lib
//
// #cgo CXXFLAGS: -I/usr/lib/llvm-19/include
// #cgo LDFLAGS: -L/usr/lib/llvm-19/lib
import "C"
