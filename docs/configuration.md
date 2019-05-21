# Configuration

The operation of the syzkaller `syz-manager` process is governed by a
configuration file, passed at invocation time with the `-config` option.
This configuration can be based on the [example](/pkg/mgrconfig/testdata/qemu.cfg);
the file is in JSON format and contains the the [following parameters](/pkg/mgrconfig/config.go).
