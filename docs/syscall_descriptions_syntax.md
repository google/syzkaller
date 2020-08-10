# Syscall description language
aka `syzlang` (`[siːzˈlæŋg]`)

Pseudo-formal grammar of syscall description:

```
syscallname "(" [arg ["," arg]*] ")" [type] ["(" attribute* ")"]
arg = argname type
argname = identifier
type = typename [ "[" type-options "]" ]
typename = "const" | "intN" | "intptr" | "flags" | "array" | "ptr" |
	   "string" | "strconst" | "filename" | "len" |
	   "bytesize" | "bytesizeN" | "bitsize" | "vma" | "proc"
type-options = [type-opt ["," type-opt]]
```

common type-options include:

```
"opt" - the argument is optional (like mmap fd argument, or accept peer argument)
```

rest of the type-options are type-specific:

```
"const": integer constant, type-options:
	value, underlying type (one of "intN", "intptr")
"intN"/"intptr": an integer without a particular meaning, type-options:
	optional range of values (e.g. "5:10", or "100:200"),
	optionally followed by an alignment parameter
"flags": a set of values, type-options:
	reference to flags description (see below), underlying int type (e.g. "int32")
"array": a variable/fixed-length array, type-options:
	type of elements, optional size (fixed "5", or ranged "5:10", boundaries inclusive)
"ptr"/"ptr64": a pointer to an object, type-options:
	direction (in/out/inout); type of the object
	ptr64 has size of 8 bytes regardless of target pointer size
"string": a zero-terminated memory buffer (no pointer indirection implied), type-options:
	either a string value in quotes for constant strings (e.g. "foo" or `deadbeef` for hex literal),
	or a reference to string flags (special value `filename` produces file names),
	optionally followed by a buffer size (string values will be padded with \x00 to that size)
"stringnoz": a non-zero-terminated memory buffer (no pointer indirection implied), type-options:
	either a string value in quotes for constant strings (e.g. "foo" or `deadbeef` for hex literal),
	or a reference to string flags,
"fmt": a string representation of an integer (not zero-terminated), type-options:
	format (one of "dec", "hex", "oct") and the value (a resource, int, flags, const or proc)
	the resulting data is always fixed-size (formatted as "%020llu", "0x%016llx" or "%023llo", respectively)
"len": length of another field (for array it is number of elements), type-options:
	argname of the object
"bytesize": similar to "len", but always denotes the size in bytes, type-options:
	argname of the object
"bitsize": similar to "len", but always denotes the size in bits, type-options:
	argname of the object
"offsetof": offset of the field from the beginning of the parent struct, type-options:
	field
"vma"/"vma64": a pointer to a set of pages (used as input for mmap/munmap/mremap/madvise), type-options:
	optional number of pages (e.g. vma[7]), or a range of pages (e.g. vma[2-4])
	vma64 has size of 8 bytes regardless of target pointer size
"proc": per process int (see description below), type-options:
	value range start, how many values per process, underlying type
"text": machine code of the specified type, type-options:
	text type (x86_real, x86_16, x86_32, x86_64, arm64)
"void": type with static size 0
	mostly useful inside of templates and varlen unions, can't be syscall argument
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

Call attributes are:

```
"disabled": the call will not be used in fuzzing; useful to temporary disable some calls
	or prohibit particular argument combinations.
"timeout[N]": additional execution timeout (in ms) for the call on top of some default value
"prog_timeout[N]": additional execution timeout (in ms) for the whole program if it contains this call;
	if a program contains several such calls, the max value is used.
"ignore_return": ignore return value of this syscall in fallback feedback; need to be used for calls
	that don't return fixed error codes but rather something else (e.g. the current time).
"breaks_returns": ignore return values of all subsequent calls in the program in fallback feedback (can't be trusted).
```

## Ints

`int8`, `int16`, `int32` and `int64` denote an integer of the corresponding size.
`intptr` denotes a pointer-sized integer, i.e. C `long` type.

By appending `be` suffix (e.g. `int16be`) integers become big-endian.

It's possible to specify a range of values for an integer in the format of `int32[0:100]` or `int32[0:4096, 512]` for a 512-aligned int.

To denote a bitfield of size N use `int64:N`.

It's possible to use these various kinds of ints as base types for `const`, `flags`, `len` and `proc`.

```
example_struct {
	f0	int8			# random 1-byte integer
	f1	const[0x42, int16be]	# const 2-byte integer with value 0x4200 (big-endian 0x42)
	f2	int32[0:100]		# random 4-byte integer with values from 0 to 100 inclusive
	f3	int32[1:10, 2]		# random 4-byte integer with values {1, 3, 5, 7, 9}
	f4	int64:20		# random 20-bit bitfield
}
```

## Structs

Structs are described as:

```
structname "{" "\n"
	(fieldname type ("(" fieldattribute* ")")? "\n")+
"}" ("[" attribute* "]")?
```

Fields can have attributes specified in parentheses after the field, independent
of their type. The only attribute is direction (`in/out/inout`). For the field for
which it is specified, the direction attributes on the upper levels are overridden.

Structs can have attributes specified in square brackets after the struct.
Attributes are:

- `packed`: the struct does not have paddings between fields and has alignment 1; this is similar to GNU C `__attribute__((packed))`; struct alignment can be overriden with `align` attribute
- `align[N]`: the struct has alignment N and padded up to multiple of `N`; contents of the padding are unspecified (though, frequently are zeros); similar to GNU C `__attribute__((aligned(N)))`
- `size[N]`: the struct is padded up to the specified size `N`; contents of the padding are unspecified (though, frequently are zeros)

## Unions

Unions are described as:

```
unionname "[" "\n"
	(fieldname type ("(" fieldattribute* ")")? "\n")+
"]" ("[" attribute* "]")?
```

Field attributes are as defined for [structs](#structs).

Unions can have attributes specified in square brackets after the union.
Attributes are:

- `varlen`: union size is the size of the particular chosen option (not statically known); without this attribute unions are statically sized as maximum of all options (similar to C unions)
- `size[N]`: the union is padded up to the specified size `N`; contents of the padding are unspecified (though, frequently are zeros)

## Resources

Resources represent values that need to be passed from output of one syscall to input of another syscall. For example, `close` syscall requires an input value (fd) previously returned by `open` or `pipe` syscall. To achieve this, `fd` is declared as a resource. This is a way of modelling dependencies between syscalls, as defining a syscall as the producer of a resource and another syscall as the consumer defines a loose sense of ordering between them. Resources are described as:

```
"resource" identifier "[" underlying_type "]" [ ":" const ("," const)* ]
```

`underlying_type` is either one of `int8`, `int16`, `int32`, `int64`, `intptr` or another resource (which models inheritance, for example, a socket is a subtype of fd). The optional set of constants represent resource special values, for example, `0xffffffffffffffff` (-1) for "no fd", or `AT_FDCWD` for "the current dir". Special values are used once in a while as resource values. If no special values specified, special value of `0` is used. Resources can then be used as types, for example:

```
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD, 1000000
resource sock[fd]
resource sock_unix[sock]

socket(...) sock
accept(fd sock, ...) sock
listen(fd sock, backlog int32)
```

Resources don't have to be necessarily returned by a syscall. They can be used as any other data type. For example:

```
resource my_resource[int32]

request_producer(..., arg ptr[out, my_resource])
request_consumer(..., arg ptr[inout, test_struct])

test_struct {
	...
	attr	my_resource
}
```

For more complex producer/consumer scenarios, field attributes can be utilized.
For example:

```
resource my_resource_1[int32]
resource my_resource_2[int32]

request_produce1_consume2(..., arg ptr[inout, test_struct])

test_struct {
	...
	field0	my_resource_1	(out)
	field1	my_resource_2	(in)
}
```

## Type Aliases

Complex types that are often repeated can be given short type aliases using the
following syntax:

```
type identifier underlying_type
```

For example:

```
type signalno int32[0:65]
type net_port proc[20000, 4, int16be]
```

Then, type alias can be used instead of the underlying type in any contexts.
Underlying type needs to be described as if it's a struct field, that is,
with the base type if it's required. However, type alias can be used as syscall
arguments as well. Underlying types are currently restricted to integer types,
`ptr`, `ptr64`, `const`, `flags` and `proc` types.

There are some builtin type aliases:
```
type bool8	int8[0:1]
type bool16	int16[0:1]
type bool32	int32[0:1]
type bool64	int64[0:1]
type boolptr	intptr[0:1]

type fileoff[BASE] BASE

type filename string[filename]

type buffer[DIR] ptr[DIR, array[int8]]
```

## Type Templates

Type templates can be declared as follows:
```
type buffer[DIR] ptr[DIR, array[int8]]
type fileoff[BASE] BASE
type nlattr[TYPE, PAYLOAD] {
	nla_len		len[parent, int16]
	nla_type	const[TYPE, int16]
	payload		PAYLOAD
} [align_4]
```

and later used as follows:
```
syscall(a buffer[in], b fileoff[int64], c ptr[in, nlattr[FOO, int32]])
```

There is builtin type template `optional` defined as:
```
type optional[T] [
	val	T
	void	void
] [varlen]
```

## Length

You can specify length of a particular field in struct or a named argument by
using `len`, `bytesize` and `bitsize` types, for example:

```
write(fd fd, buf ptr[in, array[int8]], count len[buf])

sock_fprog {
	len	len[filter, int16]
	filter	ptr[in, array[sock_filter]]
}
```

If `len`'s argument is a pointer, then the length of the pointee argument is used.

To denote the length of a field in N-byte words use `bytesizeN`, possible values
for N are 1, 2, 4 and 8.

To denote the length of the parent struct, you can use `len[parent, int8]`.
To denote the length of the higher level parent when structs are embedded into
one another, you can specify the type name of the particular parent:

```
s1 {
    f0      len[s2]  # length of s2
}

s2 {
    f0      s1
    f1      array[int32]
    f2      len[parent, int32]
}
```

`len` argument can also be a path expression which allows more complex
addressing. Path expressions are similar to C field references, but also allow
referencing parent and sibling elements. A special reference `syscall` used
in the beginning of the path allows to refer directly to the syscall arguments.
For example:

```
s1 {
	a	ptr[in, s2]
	b	ptr[in, s3]
	c	array[int8]
}

s2 {
	d	array[int8]
}

s3 {
# This refers to the array c in the parent s1.
	e	len[s1:c, int32]
# This refers to the array d in the sibling s2.
	f	len[s1:a:d, int32]
# This refers to the array k in the child s4.
	g	len[i:j, int32]
# This refers to syscall argument l.
	h	len[syscall:l, int32]
	i	ptr[in, s4]
}

s4 {
	j	array[int8]
}

foo(k ptr[in, s1], l ptr[in, array[int8]])
```

## Proc

The `proc` type can be used to denote per process integers.
The idea is to have a separate range of values for each executor, so they don't interfere.

The simplest example is a port number.
The `proc[20000, 4, int16be]` type means that we want to generate an `int16be`
integer starting from `20000` and assign `4` values for each process.
As a result the executor number `n` will get values in the `[20000 + n * 4, 20000 + (n + 1) * 4)` range.

## Integer Constants

Integer constants can be specified as decimal literals, as `0x`-prefixed
hex literals, as `'`-surrounded char literals, or as symbolic constants
extracted from kernel headers or defined by `define` directives. For example:

```
foo(a const[10], b const[-10])
foo(a const[0xabcd])
foo(a int8['a':'z'])
foo(a const[PATH_MAX])
foo(a ptr[in, array[int8, MY_PATH_MAX]])
define MY_PATH_MAX	PATH_MAX + 2
```

## Misc

Description files also contain `include` directives that refer to Linux kernel header files,
`incdir` directives that refer to custom Linux kernel header directories 
and `define` directives that define symbolic constant values.

The syzkaller executor defines some [pseudo system calls](./pseudo_syscalls.md)
that can be used as any other syscall in a description file. These pseudo
system calls expand to literal C code and can perform user-defined
custom actions. You can find some examples in
[executor/common_linux.h](../executor/common_linux.h).

Also see [tips](syscall_descriptions.md#tips) on writing good descriptions.
