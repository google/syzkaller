# Fuchsia support

To update descriptions run:
```
make extract TARGETOS=fuchsia SOURCEDIR=/path/to/fuchsia/checkout
make generate
```

To build binaries:
```
make TARGETOS=fuchsia TARGETARCH=amd64 SOURCEDIR=/path/to/fuchsia/checkout
```

To run:
```
$SOURCEDIR/out/build-zircon/tools/netcp bin/fuchsia_amd64/syz-executor :/syz-executor
$SOURCEDIR/out/build-zircon/tools/netcp bin/fuchsia_amd64/syz-stress :/syz-stress
$SOURCEDIR/out/build-zircon/tools/netruncmd : "/syz-stress -executor /syz-executor"
```
