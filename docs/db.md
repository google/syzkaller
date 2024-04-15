# syz-db

`syz-db` program can be used to manipulate corpus.db databases that are used
by syz-managers.

## Build

Build `syz-db` with `make db` or by changing to `tools/syz-db` and run `go build`.

## Options

`syz-db` currently overs the following generic arguments:

```shell
  -arch string
    	target arch
  -os string
    	target OS
  -version uint
    	database version
  -vv int
    	verbosity
```

That can be used with

```
  syz-db pack dir corpus.db
```

to pack a database

```
  syz-db unpack corpus.db dir
```

to unpack a database. A file containing performed syscalls will be returned.

```
  syz-db merge dst-corpus.db add-corpus.db* add-prog*
```

to merge databases. No additional file will be created: The first file will be replaced by the merged result.

```
  syz-db bench corpus.db
```

to run a deserialization benchmark. For example:

```
syz-db -os=linux -arch=amd64 bench corpus.db
```

could give an output like

```
allocs 123 MB (123 M), next GC 123 MB, sys heap 123 MB, live allocs 123 MB (123 M), time 324s.
```
