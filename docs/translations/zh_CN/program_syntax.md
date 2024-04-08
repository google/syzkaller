# 程序语法

Syzkaller 使用一种紧凑的的领域特定语言（DSL）来记录其执行的程序（如记录到 log0 等输出文件）、测试其代码并将程序持久化地存储在语料库中（指 corpus.db）。此页面提供了对相关程序语法的简要描述。一些有用的信息也可以在[样例程序](/sys/linux/test)和程序的[反序列化](/prog/encoding.go)中找到。


连同执行选项，该 DSL 提供了 syz-executor 运行一个程序所需要的一切。

例如：
```
r0 = syz_open_dev$loop(&(0x7f00000011c0), 0x0, 0x0)
r1 = openat$6lowpan_control(0xffffffffffffff9c, &(0x7f00000000c0), 0x2, 0x0)
ioctl$LOOP_SET_FD(r0, 0x4c00, r1)
```

该程序中的每一行描述了一个特定的系统调用的调用执行，前两个调用将返回结果存入临时变量 `r0` 和 `r1`，这两个变量将会作为调用参数传入第三个系统调用。

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

程序也可能包含空行和注释。
```
# 获取一个文件句柄
r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)

# 执行一个写操作
write(r0, &AUTO="01010101", 0x4)
```

### 内存管理

程序测试用例中的内存管理是由 Syzkaller 实现的。它会为有需要的程序分配必要大小的虚拟内存区域并且设置指针的最终参数值。

通过使用 `AUTO` 关键字，程序可以为 Syzkaller 提供对数据存储的完全掌控。例如，当一个参数必须通过引用传递但其取值的确切位置不是特别重要时，使用 `AUTO` 关键字将会很方便。

```
r1 = syz_genetlink_get_family_id$nl80211(&AUTO='nl80211\x00', 0xffffffffffffffff)
ioctl$sock_SIOCGIFINDEX_80211(r0, 0x8933, &AUTO={'wlan0\x00', <r2=>0x0})
```

此外，一些数据可以（通过指定指针的地址偏移）“锚定” 到特定的地址。当一块内存区域必须在多个调用之间共享时，这一点可能尤其重要。在这种情况下，指针地址必须设置在 0x7f0000000000 偏移处。在实际执行之前，Syzkaller 会将指针调整到实际 mmap 区域的开头。

### 调用属性

调用属性指定了有关如何执行一个特定调用的额外信息。程序中的每一个调用都有自己的调用属性集。如果未提供属性，Syzkaller 将采用默认的调用属性。

目前，Syzkaller 支持以下调用属性。

#### 错误注入
语法： `fail_nth: N`。

该属性采用（十进制的）整型参数 `N`。如果该参数为非负数，错误将会注入到第 `N` 次执行。

```
r0 = openat$6lowpan_control(0xffffffffffffff9c, &(0x7f00000000c0), 0x2, 0x0)
ioctl$LOOP_SET_FD(r0, 0x4c00, r0) (fail_nth: 5)
```

#### 异步
语法： `async`。

指示 `syz-executor` 不要等待到该调用结束而是立即继续下一个调用。

```
r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4) (async)
read(r0, &AUTO=""/4, 0x4)
close(r0)
```

设置 `async` 标志时，请注意以下注意事项：
* 带有 `async` 属性的程序只能在线程模式下执行（即必须将 `-threaded` 标志传递给 `syz-executor`）。
* 每个带有 `async` 属性的调用都在单独的线程中执行，并且有一个可用线程数量上限（`kMaxThreads = 16`）。
* 如果一个带有 `async` 属性的调用生成了资源，请记住其他的调用可能会将其作为输入。如果届时生成资源的调用尚未执行完毕，`syz-executor` 将会将 0 作为参数传入依赖该资源的调用。

**请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/program_syntax.md](/docs/program_syntax.md) 中找到。**
