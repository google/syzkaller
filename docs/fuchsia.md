# Fuchsia support

For information about checking out and building Fuchsia see
[Getting Started](https://fuchsia.googlesource.com/docs/+/master/getting_started.md)
and [Soure Code](https://fuchsia.googlesource.com/docs/+/master/development/source_code/README.md).
Image needs to be configured with sshd support:
```
fx set x64 --packages garnet/packages/products/sshd
fx full-build
```

To update descriptions run:
```
make extract TARGETOS=fuchsia SOURCEDIR=/path/to/fuchsia/checkout
make generate
```

To build binaries:
```
make TARGETOS=fuchsia TARGETARCH=amd64 SOURCEDIR=/path/to/fuchsia/checkout
```

Run `syz-manager` with a config along the lines of:
```
{
	"name": "fuchsia",
	"target": "fuchsia/amd64",
	"http": ":12345",
	"workdir": "/workdir.fuchsia",
	"kernel_obj": "/fuchsia/out/build-zircon/build-x64",
	"syzkaller": "/syzkaller",
	"image": "/fuchsia/out/x64/images/fvm.blk",
	"sshkey": "/fuchsia/out/x64/ssh-keys/id_ed25519",
	"reproduce": false,
	"cover": false,
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 10,
		"cpu": 4,
		"mem": 2048,
		"kernel": "/fuchsia/out/build-zircon/build-x64/zircon.bin",
		"initrd": "/fuchsia/out/x64/bootdata-blob.bin"
	}
}
```


## How to generate syscall description for FIDL

Syscall descriptions for FIDL are automatically generated as part of `make extract` as described above.

However, if you wish to manually generate syscall descriptions for a given `.fidl` file, do the following.

FIDL files should first be compiled into FIDL intermediate representation (JSON) files using `fidlc`:

```bash
/fuchsia/out/x64/host_x64/fidlc --json /tmp/io.json --files /fuchsia/zircon/system/fidl/fuchsia-io/io.fidl
```

Then run FIDL compiler backend `fidlgen` with syzkaller generator, which compiles a FIDL IR file into a syscall description file:

```bash
/fuchsia/out/x64/host_x64/fidlgen -generators syzkaller -json /tmp/io.json -output-base fidl_io -include-base fidl_io
```
