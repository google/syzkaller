## Headerparser

headerparser is a tool that assists in writing device system call descriptions for syzkaller.

In order to make syzkaller smarter when it comes to fuzzing a device node, you can provide it with
information about the ioctl argument struct types it expects.

However, in certain cases the number of argument struct types might be high, increasing the amount of manual
effort that goes into writing the description files for the struct types.

In order to ease the effort of writing ioctl argument type description files, headerlib does a best-effort job at
generating them for you. You will still need to manually select the appropriate syzkaller data type from the list
of types [here](/docs/syscall_descriptions_syntax.md).

## Dependencies
Headerlib uses pycparser. You can install pycparser using pip.

```shell
$ pip install pycparser
```

## Using headerparser
```shell
$ python headerparser.py --filenames=./test_headers/th_b.h
B {
          B1     len|fileoff|flags|intN     #(unsigned long)
          B2     len|fileoff|flags|intN     #(unsigned long)
}
struct_containing_union {
          something          len|fileoff|flags|int32                   #(int)
          a_union.a_char     ptr[in|out, string]|ptr[in, filename]     #(char*)
          a_union.B_ptr      ptr|buffer|array                          #(struct B*)
}
```

You can copy paste the content underneath the `Structure Metadata` over to your syzkaller device description.

## Something breaks
Let us try parsing `test_headers/th_a.h` header file to generate argument structs.

```shell
$ python headerparser.py --filenames=./test_headers/th_a.h
ERROR:root:HeaderFilePreprocessorException: /tmp/tmpW8xzty/source.o:36:2: before: some_type

$ python headerparser.py --filenames=./test_headers/th_a.h --debug
DEBUG:GlobalHierarchy:load_header_files : ['./test_headers/th_a.h']
DEBUG:HeaderFilePreprocessor:HeaderFilePreprocessor._mktempfiles: sourcefile=/tmp/tmpbBQYhR/source.cobjectfile=/tmp/tmpbBQYhR/source.o
DEBUG:HeaderFilePreprocessor:HeaderFilePreprocessor.execute: cp ./test_headers/th_a.h /tmp/tmpbBQYhR
DEBUG:HeaderFilePreprocessor:HeaderFilePreprocessor.execute: gcc -I. -E -P -c /tmp/tmpbBQYhR/source.c > /tmp/tmpbBQYhR/source.o
ERROR:root:HeaderFilePreprocessorException: /tmp/tmpbBQYhR/source.o:36:2: before: some_type
```

From the error message, we can see that the error occurs as pycparser is not aware of the type `some_type`. We can resolve this by making pycparser aware of the unknown type. In order to do this, we supply headerparser with a include file that contains C declarations and includes that can fix the parse error.

```shell
$ cat > include_file
typedef int some_type;
$ python headerparser.py --filenames=./test_headers/th_a.h --include=./include_file
A {
          B_item              ptr|buffer|array                          #(struct B*)
          char_ptr            ptr[in|out, string]|ptr[in, filename]     #(char*)
          an_unsigned_int     len|fileoff|int32                         #(unsigned int)
          a_bool              _Bool                                     #(_Bool)
          another_bool        _Bool                                     #(_Bool)
          var                 some_type                                 #(some_type)
}
```
