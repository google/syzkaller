# Syzbot DB export
Every week syzbot runs syz-reprolist to export its databases:
1. [Upstream Linux](https://syzkaller.appspot.com/upstream)
db is [here](https://storage.googleapis.com/artifacts.syzkaller.appspot.com/shared-files/repro-export/upstream.tar.gz).
2. Contact us if you want see others.

## Export structure
DB currently includes:
1. First C-Reproducer for every bug.

It doesn't include:
1. Second+ C-Reproducers for every bug.
2. Syz-Reproducers.
3. Bugs description itself.
4. Any reproducer related metadata (like triggering requirements).

## How to export more data

The best way to see more data exported is to modify the tool and send us PR with your changes.

To reproduce locally what syzbot is doing for upstream Linux:
```golang
go run ./tools/syz-reprolist/... -namespace upstream
```
Extending tools/syz-reprolist you can teach syzbot to export more.