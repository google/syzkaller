## Running syzkaller

Start the `syz-manager` process as:
```
./bin/syz-manager -config my.cfg
```

The `-config` command line option gives the location of the configuration file [described above](#configuration).

The `syz-manager` process will wind up QEMU virtual machines and start fuzzing in them.
Found crashes, statistics and other information is exposed on the HTTP address provided in manager config.

- [How to execute syzkaller programs](executing_syzkaller_programs.md)
- [How to reproduce crashes](reproducing_crashes.md)
- [How to connect several managers via Hub](connecting_several_managers.md)
