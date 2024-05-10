pathlib
========

[![Build Status](https://travis-ci.org/chigopher/pathlib.svg?branch=master)](https://travis-ci.org/chigopher/pathlib) [![go.dev reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/chigopher/pathlib) ![GitHub release (latest by date)](https://img.shields.io/github/v/release/chigopher/pathlib?style=flat-square) [![codecov](https://codecov.io/gh/chigopher/pathlib/branch/master/graph/badge.svg)](https://codecov.io/gh/chigopher/pathlib) ![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/chigopher/pathlib?style=flat-square) ![License](https://img.shields.io/github/license/chigopher/pathlib?style=flat-square)

Inspired by Python's pathlib, made better by Go.

`pathlib` is an "object-oriented" package for manipulating filesystem path objects. It takes many cues from [Python's pathlib](https://docs.python.org/3/library/pathlib.html), although it does not strictly adhere to its design philosophy. It provides a simple, intuitive, easy, and abstracted interface for dealing with many different types of filesystems.

`pathlib` is currently in the beta stage of development. The API is not guaranteed to be solidified, however changes will be as minimal as possible.

Table of Contents
-----------------


* [Examples](#examples)
  * [OsFs](#osfs)
  * [In\-memory FS](#in-memory-fs)
* [Design Philosophy](#design-philosophy)
  * [filepath\.Path](#filepathpath)
  * [filepath\.File](#filepathfile)
* [Frequently Asked Questions](#frequently-asked-questions)
  * [Why pathlib and not filepath?](#why-pathlib-and-not-filepath)
  * [Why not use afero directly?](#why-not-use-afero-directly)
  * [Does this provide any benefit to my unit tests?](#does-this-provide-any-benefit-to-my-unit-tests)
  * [What filesystems does this support?](#what-filesystems-does-this-support)



Examples
---------

### OsFs

Beacuse `pathlib` treats `afero` filesystems as first-class citizens, you can instantiate a `Path` object with the filesystem of your choosing.

#### Code

```go
package main

import (
	"fmt"
	"os"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
)

func main() {
	// Create a path on your regular OS filesystem
	path := pathlib.NewPathAfero("/home/ltclipp", afero.NewOsFs())

	subdirs, err := path.ReadDir()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	for _, dir := range subdirs {
		fmt.Println(dir.Name())
	}
}
```

#### Output

```bash
[ltclipp@landon-virtualbox examples]$ go build .
[ltclipp@landon-virtualbox examples]$ ./examples | tail
Music
Pictures
Public
Templates
Videos
git
go
mockery_test
snap
software
```

### In-memory FS

#### Code
```go
package main

import (
	"fmt"
	"os"

	"github.com/chigopher/pathlib"
	"github.com/spf13/afero"
)

func main() {
	// Create a path using an in-memory filesystem
	path := pathlib.NewPathAfero("/", afero.NewMemMapFs())
	hello := path.Join("hello_world.txt")
	hello.WriteFile([]byte("hello world!"), 0o644)

	subpaths, err := path.ReadDir()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	for _, subpath := range subpaths {
		fmt.Printf("Name: %s Mode: %o Size: %d\n", subpath.Name(), subpath.Mode(), subpath.Size())
	}

	bytes, _ := hello.ReadFile()
	fmt.Println(string(bytes))
}
```

#### Output

```bash
[ltclipp@landon-virtualbox examples]$ go build
[ltclipp@landon-virtualbox examples]$ ./examples 
Name: hello_world.txt Mode: 644 Size: 12
hello world!
```

Design Philosophy
------------------

The design philosophy of this package is to be as thin of a layer as possible to existing community-standard packages, like `io`, `afero`, and `os`. Additional functionality is provided in consise and logical ways to extend the existing community APIs. 

### `filepath.Path`

The API of `filepath.Path` can be grouped into a few main categories:

1. `github.com/spf13/afero.Fs` wrappers: these are methods that have nearly identical signatures to `afero.Fs`, with the exception of the path string (which is stored in the `pathlib.Path` object itself. `afero.Fs` is an object that is meant to interact directly with the filesystem.
2. `github.com/spf13/afero.Afero` wrappers: these are methods that again have nearly identical signatures to `afero.Afero`. `afero.Afero` is a convenience object that provides higher-level behavior to the underlying `afero.Fs` object.
3. Filesystem-specific methods: these are  methods that are implemented by some, but not all, of the afero filesystems. These methods may fail at runtime if the filesystem you provide does not implement the required interface.
4. [Python's Pathlib](https://docs.python.org/3/library/pathlib.html)-inspired methods: these are methods that are not implemented in the previous two steps, and that provide the power behind the object-oriented design. 
5. `github.com/chigopher/pathlib`-specific methods: these are miscellaneous methods that are not covered by any of the previous categories. These methods are typically conveniences around methods in one of the previous categories.

### `filepath.File`

`filepath.File` is intended to be a thin wrapper around [`afero.File`](https://pkg.go.dev/github.com/spf13/afero?tab=doc#File). We avoid simply returning this interface on calls to `Open()` and `OpenFile()` (etc) because we want the ability to extend our API beyond what `afero` provides. So, we create our own `File` object which embeds `afero.File`, but might possibly contain further functionality.

### Whoa whoa whoa, what is this afero nonsense?

[`github.com/spf13/afero`](https://github.com/spf13/afero) is a package that provides an abstracted interface to the underlying filesystem API calls. `pathlib` uses this package for operating on the abstracted filesystem. This is powerful because it allows you to to use essentially any kind of filesystem that you want. Additionally, afero is a first-class-citizen in `pathlib` meaning that you can implement and explicitly provide your own afero object. 

The basic diagram looks like this:

![Pathlib Diagram](https://github.com/chigopher/pathlib/blob/master/docs/pathlib-diagram.png)

Frequently Asked Questions
--------------------------

### Why `pathlib` and not [`filepath`](https://golang.org/pkg/path/filepath/)?

[`filepath`](https://golang.org/pkg/path/filepath/) is a package that is tightly coupled to the OS filesystem APIs and also is not written in an object-oriented way. `pathlib` uses [`afero`](https://github.com/spf13/afero) under the hood for its abstracted filesystem interface, which allows you to represent a vast array of different filesystems (e.g. SFTP, HTTP, in-memory, and of course OS filesystems) using the same `Path` object.

### Why not use `afero` directly? 

You certainly could, however `afero` does not represent a _filesystem object_ in an object-oriented way. It is only object-oriented with respect to the filesystem itself. `pathlib` is simply a thin layer on top of `afero` that provides the filesystem-object-orientation.

### Does this provide any benefit to my unit tests?

Most certainly! `pathlib` allows you to create [in-memory filesystems](#in-memory-fs), which have the nice property of being automatically garbage collected by Golang's GC when they go out of scope. You don't have to worry about defering any `Remove()` functions or setting up temporary dirs in `/tmp`. Just instantiate a `MemMapFs` and you're good to go!

### What filesystems does this support?

Currently only POSIX-style paths are supported.
