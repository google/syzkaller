### Root cause (`mm/foo.c`)

`foo_free()` frees the object in mm/foo.c:10, but **`bar()`** still uses it
afterwards (see `mm/bar.c:20-25` and include/linux/foo.h). Note that
`foo_free() in mm/foo.c:10` is not linked, and neither are /dev/foo,
https://example.com/mm/foo.c and [mm/foo.c](https://example.com).

1. `foo()` calls `foo_free()` (mm/foo.c:12).
2. `bar()` dereferences the object:
   ```c
   obj->field = 1; /* mm/bar.c:21 */
   ```

```
bar+0x10/0x20 mm/bar.c:21
```
