# Syscall descriptions syntax

Pseudo-formal grammar of syscall description:

```
syscallname "(" [arg ["," arg]*] ")" [type]
arg = argname type
argname = identifier
type = typename [ "[" type-options "]" ]
typename = "const" | "intN" | "intptr" | "flags" | "array" | "ptr" |
	   "buffer" | "string" | "strconst" | "filename" | "len" |
	   "bytesize" | "vma" | "proc"
type-options = [type-opt ["," type-opt]]
```

common type-options include:

```
"opt" - the argument is optional (like mmap fd argument, or accept peer argument)
```

rest of the type-options are type-specific:

```
"const": integer constant, type-options:
	value, underlying type (one if "intN", "intptr")
"intN"/"intptr": an integer without a particular meaning, type-options:
	optional range of values (e.g. "5:10", or "-100:200")
"flags": a set of flags, type-options:
	reference to flags description (see below)
"array": a variable/fixed-length array, type-options:
	type of elements, optional size (fixed "5", or ranged "5:10", boundaries inclusive)
"ptr"/"ptr64": a pointer to an object, type-options:
	type of the object; direction (in/out/inout)
	ptr64 has size of 8 bytes regardless of target pointer size
"buffer": a pointer to a memory buffer (like read/write buffer argument), type-options:
	direction (in/out/inout)
"string": a zero-terminated memory buffer (no pointer indirection implied), type-options:
	either a string value in quotes for constant strings (e.g. "foo"),
	or a reference to string flags,
	optionally followed by a buffer size (string values will be padded with \x00 to that size)
"filename": a file/link/dir name, no pointer indirection implied, in most cases you want `ptr[in, filename]`
"fileoff": offset within a file
"len": length of another field (for array it is number of elements), type-options:
	argname of the object
"bytesize": similar to "len", but always denotes the size in bytes, type-options:
	argname of the object
"vma": a pointer to a set of pages (used as input for mmap/munmap/mremap/madvise), type-options:
	optional number of pages (e.g. vma[7]), or a range of pages (e.g. vma[2-4])
"proc": per process int (see description below), type-options:
	value range start, how many values per process, underlying type
"text": machine code of the specified type, type-options:
	text type (x86_real, x86_16, x86_32, x86_64, arm64)
```

flags/len/flags also have trailing underlying type type-option when used in structs/unions/pointers.

Flags are described as:

```
flagname = const ["," const]*
```

or for string flags as:

```
flagname = "\"" literal "\"" ["," "\"" literal "\""]*
```

## Ints

You can use `int8`, `int16`, `int32`, `int64` and `int64` to denote an integer of the corresponding size.

By appending `be` suffix (like `int16be`) integers become big-endian.

It's possible to specify range of values for an integer in the format of `int32[0:100]`.

To denote a bitfield of size N use `int64:N`.

It's possible to use these various kinds of ints as base types for `const`, `flags`, `len` and `proc`.

```
example_struct {
	f0	int8			# random 1-byte integer
	f1	const[0x42, int16be]	# const 2-byte integer with value 0x4200 (big-endian 0x42)
	f2	int32[0:100]		# random 4-byte integer with values from 0 to 100 inclusive
	f3	int64:20		# random 20-bit bitfield
}
```

## Structs

Structs are described as:

```
structname "{" "\n"
	(fieldname type "\n")+
"}"
```

Structs can have trailing attributes `packed` and `align_N`, they are specified in square brackets after the struct.

## Unions

Unions are described as:

```
unionname "[" "\n"
	(fieldname type "\n")+
"]"
```

Unions can have a trailing "varlen" attribute (specified in square brackets after the union),
which means that union length is not maximum of all option lengths,
but rather length of a particular chosen option.

## Resources

Custom resources are described as:

```
resource identifier "[" underlying_type "]" [ ":" const ("," const)* ]
```

`underlying_type` is either one of `int8`, `int16`, `int32`, `int64`, `intptr` or another resource.
Resources can then be used as types. For example:

```
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD, 1000000
resource sock[fd]
resource sock_unix[sock]

socket(...) sock
accept(fd sock, ...) sock
listen(fd sock, backlog int32)
```

## Length

You can specify length of a particular field in struct or a named argument by using `len` and `bytesize` types, for example:

```
write(fd fd, buf buffer[in], count len[buf]) len[buf]

sock_fprog {
	len	len[filter, int16]
	filter	ptr[in, array[sock_filter]]
}
```

If `len`'s argument is a pointer (or a `buffer`), then the length of the pointee argument is used.

To denote the length of a field in N-byte words use `bytesizeN`, possible values for N are 1, 2, 4 and 8.

To denote the length of the parent struct, you can use `len[parent, int8]`.
To denote the length of the higher level parent when structs are embedded into one another, you can specify the type name of the particular parent:

```
struct s1 {
    f0      len[s2]  # length of s2
}

struct s2 {
    f0      s1
    f1      array[int32]
}

```

## Proc

The `proc` type can be used to denote per process integers.
The idea is to have a separate range of values for each executor, so they don't interfere.

The simplest example is a port number.
The `proc[20000, 4, int16be]` type means that we want to generate an `int16be`
integer starting from `20000` and assign `4` values for each process.
As a result the executor number `n` will get values in the `[20000 + n * 4, 20000 + (n + 1) * 4)` range.

## Misc

Description files also contain `include` directives that refer to Linux kernel header files,
`incdir` directives that refer to custom Linux kernel header directories 
and `define` directives that define symbolic constant values.
