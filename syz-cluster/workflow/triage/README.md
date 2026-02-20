## Ephemeral disk size usage estimations for Linux

```
$ git fetch origin +refs/tags/torvalds-head:refs/tags/torvalds-head --depth=1
$ du -h .
260M    .
$ git checkout torvalds-head
$ du -h .
2G      .
$ git fetch origin 2dde18cd1d8fac735875f2e4987f11817cc0bc2c --depth=1
$ du -h .
2.1G    .
$ git checkout 2dde18cd1d8fac735875f2e4987f11817cc0bc2c
$ du -h .
2G      .
```

## Without cloning the repository

```
mkdir ~/shallow-repo ~/shallow-repo/.git ~/shallow-repo/workdir ~/overlayfs
mount -t tmpfs -o size=128M tmpfs /root/overlayfs
mkdir ~/overlayfs/upper ~/overlayfs/work
mount -t overlay overlay -o lowerdir=/kernel-repo,upperdir=/root/overlayfs/upper,workdir=/root/overlayfs/work /root/shallow-repo/.git
git --git-dir=/root/shallow-repo/.git --work-tree=/root/shallow-repo/workdir checkout master
```

Needs:

```
        securityContext:
          capabilities:
            add: ["SYS_ADMIN"]
```
