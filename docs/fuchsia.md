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
