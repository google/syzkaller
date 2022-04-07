// Package gofuzzdep contains the business logic used to monitor the fuzzing.
//
// It is handled specially by go-fuzz-build; see the comments in package go-fuzz-defs.
//
// Be particularly careful about adding imports to go-fuzz-dep:
// Any package imported by go-fuzz-dep cannot be instrumented (on pain of import cycles),
// which reduces the effectiveness of go-fuzz on any other package that imports it.
// That is why (e.g.) there are hand-rolled serialization functions instead of using encoding/binary,
// and hand-rolled syscall-based communication instead of using package net or os.
package gofuzzdep
