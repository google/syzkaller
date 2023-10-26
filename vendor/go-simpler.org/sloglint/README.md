# sloglint

[![checks](https://github.com/go-simpler/sloglint/actions/workflows/checks.yml/badge.svg)](https://github.com/go-simpler/sloglint/actions/workflows/checks.yml)
[![pkg.go.dev](https://pkg.go.dev/badge/go-simpler.org/sloglint.svg)](https://pkg.go.dev/go-simpler.org/sloglint)
[![goreportcard](https://goreportcard.com/badge/go-simpler.org/sloglint)](https://goreportcard.com/report/go-simpler.org/sloglint)
[![codecov](https://codecov.io/gh/go-simpler/sloglint/branch/main/graph/badge.svg)](https://codecov.io/gh/go-simpler/sloglint)

A Go linter that ensures consistent code style when using `log/slog`.

## 📌 About

The `log/slog` API allows two different types of arguments: key-value pairs and attributes.
People may have different opinions about which one is better,
but nobody probably wants to mix them up because it makes the code harder to read.

```go
slog.Info("a user has logged in", "user_id", 42, slog.String("ip_address", "192.0.2.0")) // ugh
```

`sloglint` finds such function calls and checks that all the arguments are either key-value pairs or attributes.
The linter has several options, so you can adjust it to your own code style.

## 🚀 Features

* Forbid mixing key-value pairs and attributes within a single function call (default)
* Enforce using either key-value pairs or attributes for the entire project (optional)
* Enforce using constants instead of raw keys (optional)
* Enforce putting arguments on separate lines (optional)

## 📦 Install

Download a prebuilt binary from the [Releases][1] page.

## 📋 Usage

```shell
sloglint [flags] ./...
```

### Key-value pairs only

The `-kv-only` flag causes `sloglint` to report any use of attributes.

```go
slog.Info("a user has logged in", slog.Int("user_id", 42)) // sloglint: attributes should not be used
```

### Attributes only

In contrast, the `-attr-only` flag causes `sloglint` to report any use of key-value pairs.

```go
slog.Info("a user has logged in", "user_id", 42) // sloglint: key-value pairs should not be used
```

### No raw keys

To prevent typos, you may want to forbid the use of raw keys altogether.
The `-no-raw-keys` flag causes `sloglint` to report the use of strings as keys (including `slog.Attr` calls, e.g. `slog.Int("user_id", 42)`).

```go
slog.Info("a user has logged in", "user_id", 42) // sloglint: raw keys should not be used
```

This report can be fixed by using either constants...

```go
const UserId = "user_id"

slog.Info("a user has logged in", UserId, 42)
```

...or custom `slog.Attr` constructors.

```go
func UserId(value int) slog.Attr { return slog.Int("user_id", value) }

slog.Info("a user has logged in", UserId(42))
```

> 💡 Such helpers can be automatically generated for you by the [`sloggen`][2] tool. Give it a try too!

### Arguments on separate lines

To improve code readability, you may want to put arguments on separate lines, especially when using key-value pairs.
The `-args-on-sep-lines` flag causes `sloglint` to report 2+ arguments on the same line.

```go
slog.Info("a user has logged in", "user_id", 42, "ip_address", "192.0.2.0") // sloglint: arguments should be put on separate lines
```

This report can be fixed by reformatting the code.

```go
slog.Info("a user has logged in",
    "user_id", 42,
    "ip_address", "192.0.2.0",
)
```

[1]: https://github.com/go-simpler/sloglint/releases
[2]: https://github.com/go-simpler/sloggen
