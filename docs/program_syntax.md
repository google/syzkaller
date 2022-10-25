# Program syntax

Syzkaller uses a compact domain-specific language (DSL) for programs
to log executed programs, test its code, and persist programs in the
corpus. This page provides a brief description of the corresponding
syntax. Some useful information can also be found in the
[existing examples](/sys/linux/test) and in the program
[deserialization code](/prog/encoding.go).

Together with execution options, the DSL provides everything that
syz-executor needs to run a program.

For example, consider the program:
```
r0 = syz_open_dev$loop(&(0x7f00000011c0), 0x0, 0x0)
r1 = openat$6lowpan_control(0xffffffffffffff9c, &(0x7f00000000c0), 0x2, 0x0)
ioctl$LOOP_SET_FD(r0, 0x4c00, r1)
```

Each line in this program describes a particular syscall invocation,
with the first two calls saving the result in temporary variables `r0`
and `r1`, which are passed to the third call.

```
line = assignment | call
assignment = variable " = " call
call = syscall-name "(" [arg ["," arg]*] ")"  ["(" [call-prop ["," call-prop*] ")"]
arg = "nil" | "AUTO" | const-arg | resource-arg | result-arg | pointer-arg | string-arg | struct-arg | array-arg | union-arg
const-arg = "0x" hex-integer
resource-arg = variable ["/" hex-integer] ["+" hex-integer]
result-arg = "<" variable "=>" arg
pointer-arg = "&" pointer-arg-addr ["=ANY"] "=" arg
pointer-arg-addr = "AUTO" | "(" pointer-addr ["/" region-size] ")"
string-arg = "'" escaped-string "'" | "\"" escaped-string "\"" | "\"$" escaped-string "\""
struct-arg =  "{" [arg ["," arg]*] "}"
array-arg = "[" [arg ["," arg]*] "]"
union-arg = "@" field-name ["=" arg]
call-prop = prop-name ": " prop-value
variable = "r" dec-integer
pointer-addr = hex-integer
region-size = hex-integer
```

Programs may also contain blank lines and comments.
```
# Obtain a file handle
r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)

# Perform a write operation
write(r0, &AUTO="01010101", 0x4)
```

### Memory management

Memory management is performed by syzkaller itself. It will allocate
virtual memory regions of the necessary size and set the final values
of pointer arguments.

By using the `AUTO` keyword, programs can give syzkaller the full
control over storing the data. This may be convenient e.g. when a
parameter must be passed by reference, but the exact location of its
value is not of particular importance.

```
r1 = syz_genetlink_get_family_id$nl80211(&AUTO='nl80211\x00', 0xffffffffffffffff)
ioctl$sock_SIOCGIFINDEX_80211(r0, 0x8933, &AUTO={'wlan0\x00', <r2=>0x0})
```

Alternatively, some data can be "anchored" to specific addresses. It
may be especially important when a memory region must be shared
between multiple calls.  In this case, pointer addresses must be given
at the 0x7f0000000000 offset. Before the actual execution, syzkaller
will adjust pointers to the start of the actual mmap'ed region.

### Call properties

Call properties specify extra information about how a specific call
must be executed. Each call within a program has its own set of call
properties. If no properties are provided, syzkaller takes the default
ones.

Currently, syzkaller supports the following call properties.

#### Fault injection
Syntax: `fail_nth: N`.

It takes an integer (base 10) argument `N`. If the argument is
non-negative, a fault will be injected into the `N`-th occasion.

```
r0 = openat$6lowpan_control(0xffffffffffffff9c, &(0x7f00000000c0), 0x2, 0x0)
ioctl$LOOP_SET_FD(r0, 0x4c00, r0) (fail_nth: 5)
```

#### Async
Syntax: `async`.

Instructs `syz-executor` not to wait until the call completes and
to proceed immediately to the next call.

```
r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4) (async)
read(r0, &AUTO=""/4, 0x4)
close(r0)
```

When setting `async` flags be aware of the following considerations:
* Such programs should only be executed in threaded mode (i.e. `-threaded`
flag must be passed to `syz-executor`.
* Each `async` call is executed in a separate thread and there's a
limited number of available threads (`kMaxThreads = 16`).
* If an `async` call produces a resource, keep in mind that some other call
might take it as input and `syz-executor` will just pass 0 if the resource-
producing call has not finished by that time.
