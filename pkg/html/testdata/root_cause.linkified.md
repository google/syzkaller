### Root cause ([`mm/foo.c`](https://github.com/google/syzkaller/blob/111222/mm/foo.c#L0))

`foo_free()` frees the object in [mm/foo.c:10](https://github.com/google/syzkaller/blob/111222/mm/foo.c#L10), but **`bar()`** still uses it
afterwards (see [`mm/bar.c:20-25`](https://github.com/google/syzkaller/blob/111222/mm/bar.c#L20) and [include/linux/foo.h](https://github.com/google/syzkaller/blob/111222/include/linux/foo.h#L0)). Note that
`foo_free() in mm/foo.c:10` is not linked, and neither are /dev/foo,
https://example.com/mm/foo.c and [mm/foo.c](https://example.com).

1. `foo()` calls `foo_free()` ([mm/foo.c:12](https://github.com/google/syzkaller/blob/111222/mm/foo.c#L12)).
2. `bar()` dereferences the object:
   ```c
   obj->field = 1; /* mm/bar.c:21 */
   ```

```
bar+0x10/0x20 mm/bar.c:21
```
