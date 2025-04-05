> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/syscall_descriptions_syntax.md](/docs/syscall_descriptions_syntax.md) 中找到。**

# Syscall description language
又称作 `syzlang` (`[siːzˈlæŋg]`)

系统调用描述的伪形式语法：

```
syscallname "(" [arg ["," arg]*] ")" [type] ["(" attribute* ")"]
arg = argname type
argname = identifier
type = typename [ "[" type-options "]" ]
typename = "const" | "intN" | "intptr" | "flags" | "array" | "ptr" |
	   "string" | "strconst" | "filename" | "glob" | "len" |
	   "bytesize" | "bytesizeN" | "bitsize" | "vma" | "proc" |
	   "compressed_image"
type-options = [type-opt ["," type-opt]]
```

常见的类型选项（type-options）包括:

```
"opt" - 该参数是可选的（如 mmap fd 参数，或 accept peer 参数）
```

其余的类型选项是类型特定的：

> 注：为了便于理解，每个类型选项下方都附带了从 syzlang 中挑选的相关示例，类型选项由"[]"包裹。

```
"const": 整型常量，类型选项:
	值，基础类型（"intN" 或 "intptr"）
示例：const[0, int32] 或 ioctl$I2C_TIMEOUT(..., cmd const[I2C_TIMEOUT], ...)，其中 I2C_TIMEOUT 为 dev_i2c.txt.const 定义的常量
"intN"/"intptr": 没有特定含义的整数，类型选项：
	一个可选值范围（例如 "5:10" 或 "100:200"）
	或者一个标志描述的引用（见下文），
	或单个值
	如果使用范围，其后可选择性地跟对齐参数
示例：int8[100:200] 或 ioctl$UI_SET_KEYBIT(..., arg intptr[0:KEY_MAX])
"flags": 一组值，类型选项：
	标志描述的引用（见下文），基本的整型类型（例如 "int32"）
示例：flags[iocb_flags, int32]，其中 iocb_flags = IOCB_FLAG_RESFD, IOCB_FLAG_IOPRIO
"array": 可变/固定长度数组，类型选项：
	元素类型，可选尺寸（固定为 "5"，或范围限定为 "5:10"的闭区间）
示例：array[int8, 5] 或 array[int8, 5:10]
"ptr"/"ptr64": 指向对象的指针，类型选项:
	方向（输入/输出/输入输出）；对象的类型
	ptr64 的大小为 8 字节，与目标指针大小无关
示例：io_getevents(..., timeout ptr[in, timespec, opt])，其中 opt 表示该参数是可选的
"string": 以零结尾的内存缓冲区（不包含指针间接寻址），类型选项：
	一个常量字符串的引号中的字符串值（例如，"foo" 或 十六进制的`deadbeef`），
	或一个对字符串标志的引用（特殊值 `filename` 将产生文件名），后面可跟着一个缓冲区大小（字符串值将用 \x00 填充到该大小）
示例：mount$9p_tcp(src ptr[in, string["127.0.0.1"]], ...)
"stringnoz": 非零终止的内存缓冲区（不包含指针间接寻址），类型选项：
	一个常量字符串的引号中的字符串值（例如，"foo" 或 十六进制的`deadbeef`），
	或一个对字符串标志的引用
示例：stringnoz[cgroup_subsystems]，其中 cgroup_subsystems = "cpu", "memory", "io", ...
"glob": 要在目标文件上匹配的 glob 模式，类型选项：
	一个引号中的模式字符串（语法参考：https://golang.org/pkg/path/filepath/#Match，例如，"/sys/" 或 "/sys/**/*"）
	也可以指定排除的 glob（例如 "/sys/**/*：-/sys/power/state"）
示例：openat$sysfs(..., dir ptr[in, glob["/sys/**/*:-/sys/power/state"]], ...)
"fmt": 整数的字符串表示形式（非零终止），类型选项：
	格式（"dec"、"hex"、"oct" 之一）和值（resource、int、flags、const 或 proc）
	其结果数据总是大小固定的（分别对应地格式化为 "%020llu", "0x%016llx" 或 "%023llo"）
示例：fmt[hex, int32] 或 fmt[dec, proc[10, 20]]
"len": 另一个字段的长度（对于数组，它是元素的数量），类型选项：
	对象的参数名称（argname）
示例：mmap$xdp(addr vma, len len[addr], ...) 或 read(..., buf buffer[out], count len[buf])
"bytesize": 类似于 "len"，但总是以字节为单位表示大小，类型选项：
	对象的参数名称（argname）
示例：getsockopt$XDP_STATISTICS(..., val ..., len ptr[in, bytesize[val, int32]])
"bitsize": 类似于 "len"，但总是以位为单位表示大小，类型选项：
	对象的参数名称（argname）
示例：bitsize[key, int16]，其中 key 为 array[int8]
"offsetof": 字段与父类结构体头部的偏移量，类型选项：
	字段（field）
示例：offsetof[ebt_among_info:FIELD, int32]，其中 FILELD 为 ebt_among_info 的某个结构体成员（通过 : 的成员索引支持嵌套，如 offsetof[A:B:C, int32]）
"vma"/"vma64": 指向一组页面的指针（用作 mmap/munmap/mremap/madvice 的输入），类型选项：
	可选的页面数量（例如 vma[7]）或页面范围（例如 vma[2-4]）
	vma64 的大小为 8 字节，与目标指针大小无关
示例：mmap$KVM_VCPU(addr vma, ...) 或 syz_kvm_setup_cpu$x86(..., usermem vma[24], ...)
"proc": 每个进程的int值（参阅下面的描述），类型选项:
	值范围的起始，每个进程有多少个值，基础类型
示例：proc[0x0, 4, int8]
"compressed_image": zlib 压缩的磁盘映像
	接受 `compressed_image` 作为参数的系统调用必须被标记为 `no_generate` 和 `no_minimize` 调用属性。
示例：syz_mount_image$f2fs(..., img ptr[in, compressed_image]) fd_dir (timeout[4000], no_generate, no_minimize)
"text": 指定类型的机器码，类型选项:
	文本类型 (x86_real, x86_16, x86_32, x86_64, arm64)
示例：ptr[in, text[x86_64]]
"void": 静态大小为 0 的类型
	主要用于模板和 varlen 联合体内部，不能作为系统调用的参数
示例：write$FUSE_INTERRUPT(..., arg ptr[in, fuse_out[void]], ...)
```

在 structs/unions/pointers 中使用时，flags/len/flags 也有尾随的基础类型的类型选项。

标志描述为:

```
flagname = const ["," const]*
```

或者对于字符串标志：

```
flagname = "\"" literal "\"" ["," "\"" literal "\""]*
```

调用属性如下所示：

```
"disabled": 该调用将不会被用于模糊测试；用于临时禁用某些调用或禁止特定参数组合。
"timeout[N]": 对该调用在默认值的基础上的额外执行超时（以毫秒为单位）。
"prog_timeout[N]": 对包含该调用的整个程序的额外执行超时（以毫秒为单位）；如果程序包含多个这样的调用，则使用其最大值。
"ignore_return": 在回退反馈中忽略该系统调用的返回值；用于不返回固定错误代码而返回其他内容（如当前时间）的调用。
"breaks_returns": 在回退反馈中忽略程序中所有后续调用的返回值（不可信）。
"no_generate": 不要尝试生成该系统调用，即只使用种子描述来生成它。
"no_minimize": 在试图最小化崩溃程序时，请勿修改该系统调用的实例。
```

## Ints

`int8`，`int16`，`int32` 和 `int64` 表示相应大小的整数。
`intptr` 表示指针大小的整数，即 C 的 `long` 类型。（译者注：intptr 不是指针，而是相当于 C 的 `size_t`）

通过追加 `be` 后缀（例如 `int16be`），整数就变成了大端序。

可以为整数指定一个数值范围，格式为 `int32[0:100]` 或 `int32[0:4096, 512]`（对于 512 对齐的 int）（译者注：int32[0:4096, 512] 意为其取值为{0,512,1024,...}）。

整数的第一个类型选项也可以是对标志说明或数值的引用。在这种情况下，不支持对齐参数。

使用 `int64:N` 表示大小为 N 的位域。

可以将这些不同类型的 ints 作为 `const`、`flags`、`len` 和 `proc` 的基类型。

```
example_struct {
	f0	int8			# 随机 1 字节整数
	f1	const[0x42, int16be]	# 2 字节整数常量，值为 0x4200（大端序 0x42）
	f2	int32[0:100]		# 随机 4 字节整数，取值范围为 0 至 100（含 100）
	f3	int32[1:10, 2]		# 值为 {1、3、5、7、9} 的随机 4 字节整数
	f4	int64:20		# 随机 20 位域
	f5	int8[10]		# 1 字节整数常量，值为 10
	f6	int32[flagname]		# flagname 所引用的值集中的随机 4 字节整数
}
```

## Structs

结构体描述为：

```
structname "{" "\n"
	(fieldname type ("(" fieldattribute* ")")? (if[expression])? "\n")+
"}" ("[" attribute* "]")?
```
> 注："?"表示匹配前面的子表达式零次或一次，"+"表示匹配前面的子表达式一次或多次

字段可以在字段后的括号中指定属性，与字段类型无关。`in/out/inout` 属性指定每个字段的方向，例如：

```
foo {
	field0	const[1, int32]	(in)
	field1	int32		(inout)
	field2	fd		(out)
}
```

你可以指定决定是否包含某个字段的条件：

```
foo {
	field0	int32
	field1	int32 (if[value[field0] == 0x1])
}
```

参阅 [相应章节](syscall_descriptions_syntax.md#conditional-fields) 了解更多详情。

`out_overlay` 属性允许为结构体设置独立的输入和输出布局。在 `out_overlay` 字段之前的字段为输入字段，从 `out_overlay` 开始的字段为输出字段。输入字段和输出字段在内存中重叠（都从内存中结构体的起始位置开始）。例如：

```
foo {
	in0	const[1, int32]
	in1	flags[bar, int8]
	in2	ptr[in, string]
	out0	fd	(out_overlay)
	out1	int32
}
```

结构体后面的方括号中可以指定属性。属性包括：

- `packed`: 结构体的字段之间没有填充，对齐方式为 1；这类似于 GNU C 的 `__attribute__((packed))`；结构体的对齐方式可以用 `align` 属性覆盖
- `align[N]`: 结构体的对齐方式为 N，填充为 `N` 的倍数；填充内容未指定（但通常为零）；类似于 GNU C 的`__attribute__((aligned(N)))`。
- `size[N]`: 结构体被填充到指定的大小 `N`；填充内容未指定（但通常为零）

## Unions

联合体被描述为：

```
unionname "[" "\n"
	(fieldname type (if[expression])? "\n")+
"]" ("[" attribute* "]")?
```

在模糊测试过程中，syzkaller 会随机从联合体中选择一个选项。

你还可以指定一些条件，根据其他字段的值来决定相应的选项是否被选中的条件。参见 [相应章节](syscall_descriptions_syntax.md#conditional-fields) 了解更多详情。

联合体后的方括号中可以指定属性。属性包括：

- `varlen`: 联合体大小是所选特定选项的大小（非静态已知）；如果没有该属性，联合体的大小是所有字段中的最大值（类似于 C 联合体）。
- `size[N]`: 联合体的填充大小为指定的 `N`；填充内容未指定（但通常为零）

## Resources

资源代表需要从一个系统调用的输出传递到另一个系统调用的输入的值。例如，`close` 系统调用需要先前由 `open` 或 `pipe` 系统调用返回的值作为输入（fd）。为此，`fd` 被声明为一种资源。这是模拟系统调用之间依赖关系的一种方式，因为将一个系统调用定义为资源的生产者，而将另一个系统调用定义为消费者，就定义了它们之间一种宽松的调用顺序。资源被描述为：

```
"resource" identifier "[" underlying_type "]" [ ":" const ("," const)* ]
```

`underlying_type` 是 `int8`、`int16`、`int32`、`int64`、`intptr` 或其他资源（继承模型，例如，socket 是 fd 的子类型）之一。常量的可选集代表资源的特殊值，例如，`0xffffffffffffffffff`（-1）表示 “无 fd”，`AT_FDCWD`表示 “当前目录”。特殊值偶尔会作为资源值使用。如果没有指定特殊值，则使用特殊值 `0`。资源可以用作类型，例如：

```
resource fd[int32]: 0xffffffffffffffff, AT_FDCWD, 1000000
resource sock[fd]
resource sock_unix[sock]

socket(...) sock
accept(fd sock, ...) sock
listen(fd sock, backlog int32)
```

资源不一定要由系统调用返回。它们可以像其他数据类型一样使用。例如：

```
resource my_resource[int32]

request_producer(..., arg ptr[out, my_resource])
request_consumer(..., arg ptr[inout, test_struct])

test_struct {
	...
	attr	my_resource
}
```

对于更复杂的生产者/消费者场景，可以使用字段属性。例如：

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

每种资源类型（联合体和可选指针除外）必须被至少一个系统调用 “生产”（用作输出），并被至少一个系统调用 “消费”（用作输入）。

## Type Aliases

对于经常重复的复杂类型，可以使用以下语法给出简短的类型别名：

```
type identifier underlying_type
```

例如:

```
type signalno int32[0:65]
type net_port proc[20000, 4, int16be]
```

这样，在任何情况下都可以使用类型别名来代替基础类型。基础类型需要像结构体字段一样进行描述，即带有基础类型（如果需要的话）。此外，类型别名也可以用作系统调用参数。基础类型目前仅限于整数类型、`ptr`、`ptr64`、`const`、`flags` 和 `proc` 类型。

以下是一些内置的类型别名：
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

类型模板的声明方式如下：
```
type buffer[DIR] ptr[DIR, array[int8]]
type fileoff[BASE] BASE
type nlattr[TYPE, PAYLOAD] {
	nla_len		len[parent, int16]
	nla_type	const[TYPE, int16]
	payload		PAYLOAD
} [align_4]
```

随后按如下方式使用：
```
syscall(a buffer[in], b fileoff[int64], c ptr[in, nlattr[FOO, int32]])
```

内置类型模板 `optional` 定义如下：
```
type optional[T] [
	val	T
	void	void
] [varlen]
```

## Length

你可以使用 `len`、`bytesize` 和`bitsize` 类型指定结构体或命名参数中特定字段的长度，例如：

```
write(fd fd, buf ptr[in, array[int8]], count len[buf])

sock_fprog {
	len	len[filter, int16]
	filter	ptr[in, array[sock_filter]]
}
```

如果 `len` 的参数是指针，则使用被指向参数的长度。

用 `bytesizeN` 表示字段的 N 字节长度，N 的可能值为 1、2、4 和 8。

要表示父结构体的长度，可以使用 `len[parent, int8]`。当结构体相互嵌入时，要表示上一级父结构体的长度，可以指定特定父结构体的类型名称：

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

`len` 参数也可以是一个路径表达式，它允许更复杂的寻址。路径表达式类似于 C 语言的字段引用，但也允许引用父元素和同级元素。在路径开头使用特殊引用 `syscall` 可以直接引用 syscall 参数。例如：

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
# 这里指的是父结构体 s1 中的数组 c。
	e	len[s1:c, int32]
# 这里指的是同级结构体 s2 中的数组 d。
	f	len[s1:a:d, int32]
# 这里指的是子结构体 s4 中的数组 k。
	g	len[i:j, int32]
# 这里指的是系统调用参数 l。
	h	len[syscall:l, int32]
	i	ptr[in, s4]
}

s4 {
	j	array[int8]
}

foo(k ptr[in, s1], l ptr[in, array[int8]])
```

## Proc

`proc` 类型可用于表示每个进程的整数。这样设计的目的是为每个执行器设置独立的数值范围，使它们互不干扰。

最简单的例子就是端口号。`proc[20000, 4, int16be]` 类型意味着我们要生成一个从 `20000` 开始的 `int16be` 整数，并为每个进程分配 `4` 个值。因此，执行器中的数 `n` 的取值范围为 `[20000 + n * 4, 20000 + (n + 1) * 4)`。

## Integer Constants

整数常量可指定为十进制字面量、`0x` 前缀的十六进制字面量、`'` 包围的字符字面量或从内核头文件中提取或由 `define` 指令定义的符号常量。例如：

```
foo(a const[10], b const[-10])
foo(a const[0xabcd])
foo(a int8['a':'z'])
foo(a const[PATH_MAX])
foo(a int32[PATH_MAX])
foo(a ptr[in, array[int8, MY_PATH_MAX]])
define MY_PATH_MAX	PATH_MAX + 2
```

## Conditional fields

### In structures

在 syzlang 中，可以为每个结构字段指定一个条件，以决定是否包含该字段：

```
header_fields {
  magic       const[0xabcd, int16]
  haveInteger int8
} [packed]

packet {
  header  header_fields
  integer int64  (if[value[header:haveInteger] == 0x1])
  body    array[int8]
} [packed]

some_call(a ptr[in, packet])
```

在本例中，只有当 `header.haveInteger == 1` 时，`packet` 结构才会包含 `integer` 字段。在内存中，`packet` 的布局如下：

| header_files.magic = 0xabcd | header_files.haveInteger = 0x1 | integer | body |
| - | - | - | - |


这相当于以下程序：
```
some_call(&AUTO={{AUTO, 0x1}, @value=0xabcd, []})
```

如果 `header.haveInteger` 不是 `1`，syzkaller 会假装字段 `integer` 不存在。
```
some_call(&AUTO={{AUTO, 0x0}, @void, []})
```

| header_files.magic = 0xabcd | header_files.haveInteger = 0x0 | body |
| - | - | - |

每个条件字段的长度都被假设为可变的，以及该字段所属的结构的长度也是可变的。

当一个变长字段出现在结构体中间时，结构体必须用 `[packed]` 标记。

禁止在位域上设置条件：
```
struct {
  f0 int
  f1 int:3 (if[value[f0] == 0x1])  # It will not compile.
}
```

但你可以在条件中引用位域：
```
struct {
  f0 int:1
  f1 int:7
  f2 int   (if[value[f0] == value[f1]])
} [packed]
```

### In unions

让我们来看看下面这个例子。

```
struct {
  type int
  body alternatives
}

alternatives [
  int     int64 (if[value[struct:type] == 0x1])
  arr     array[int64, 5] (if[value[struct:type] == 0x2])
  default int32
] [varlen]

some_call(a ptr[in, struct])
```

在这种情况下，将根据 `type` 字段的值选择联合体选项。例如，如果 `type` 是 `0x1`，那么 `alternatives` 类型可以是 `int` 或 `default`：
```
some_call(&AUTO={0x1, @int=0x123})
some_call(&AUTO={0x1, @default=0x123})
```

如果 `type` 是 `0x2`，则 `alternatives` 类型可以是 `arr` 或 `default`。

如果 `type` 既不是 `0x1` 也不是 `0x2`，syzkaller 只能选择 `default` 作为 `alternatives` 类型：
```
some_call(&AUTO={0x0, @default=0xabcd})
```

为确保总是可以构建联合体，最后一个联合字段**必须总是没有条件的**。

因此，下面的定义将无法编译：

```
alternatives [
  int int64 (if[value[struct:type] == 0x1])
  arr array[int64, 5] (if[value[struct:type] == 0x1])
] [varlen]
```

在变异和生成程序的过程中，syzkaller 会随机选择一个满足条件的联合字段。


### Expression syntax

目前，只支持 `==`、`!=` 和 `&` 操作符。不过，该功能被设计得可以便捷地添加更多运算符。如有需要，请随时提交 GitHub issue 或给我们发邮件。

表达式以 `int64` 值求值。如果一个表达式的最终结果不是 0，则假定该表达式被满足。

如果要引用字段的值，可以通过 `value[path:to:field]`，这与 `len[]` 参数类似。

```
sub_struct {
  f0 int
  # 引用父结构中的一个字段。
  f1 int (if[value[struct:f2]]) # 与 if[value[struct:f2] != 0] 相同。
}

struct {
  f2 int
  f3 sub_struct
  f4 int (if[value[f2] == 0x2]) # 引用一个同级字段。
  f5 int (if[value[f3:f0] == 0x1]) # 引用一个嵌套字段。
} [packed]

call(a ptr[in, struct])
```

被引用的字段必须是整型，且其引用路径中不能有条件字段。
条件字段。例如，以下描述将无法编译。

```
struct {
  f0 int
  f1 int (if[value[f0] == 0x1])
  f2 int (if[value[f1] == 0x1])
}
```

你也可以在表达式中引用常量：
```
struct {
  f0 int
  f1 int
  f2 int (if[value[f0] & SOME_CONST == OTHER_CONST])
}
```

## Meta

描述文件还可以包含 `meta` 指令，用于指定整个文件的元信息。

```
meta noextract
```
告诉 `make extract` 不提取此文件的常量。尽管如此，仍可在此文件上手动调用 `syz-extract` 。

```
meta arches["arch1", "arch2"]
```
将此文件限制在给定的体系结构中。在其他架构上，`make extract` 和 `make generate` 不会使用该文件。

## Misc

描述文件还包含指向 Linux 内核头文件的 `include` 指令、指向自定义 Linux 内核头文件目录的 `incdir` 指令和定义符号常量值的 `define` 指令。

syzkaller 执行器定义了一些[伪系统调用](/docs/pseudo_syscalls.md)，可以像描述文件中的其他系统调用一样使用。这些伪系统调用可扩展为 C 代码，并可执行用户自定义的操作。你可以在 [executor/common_linux.h](/executor/common_linux.h) 中找到一些例子。

另请参阅 [tips](/docs/syscall_descriptions.md#tips)，了解如何编写好的描述。
