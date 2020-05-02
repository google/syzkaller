# Setup

Instructions for running OpenBSD host, OpenBSD vm, amd64 kernel.
In addition, the host must be running `-current`.

Variables used throughout the instructions:

- `$KERNEL` - Custom built kernel, see [Compile Kernel](#compile-kernel).
              Defaults to `/sys/arch/amd64/compile/SYZKALLER/obj/bsd` if the
              instructions are honored.
- `$SSHKEY` - SSH key ***without a passphrase*** used to connect to the VMs,
              it's advised to use a dedicated key.
- `$USER`   - The name of the user intended to run syzkaller.
- `$VMIMG`  - VM disk image.
- `$VMID`   - The numeric ID of last started VM.

## Install syzkaller

1. Install dependencies:

   ```sh
   # pkg_add git gmake go
   ```

   In order for reproducers to work, GCC from ports is also required:

   ```sh
   # pkg_add gcc
   ```

2. Clone repository:

   ```sh
   $ go get -u -d github.com/google/syzkaller/prog
   $ cd ~/go/src/github.com/google/syzkaller
   $ gmake all
   ```

## Compile Kernel

A `GENERIC` kernel must be compiled with
[kcov(4)](https://man.openbsd.org/kcov.4)
enabled:

```sh
$ cd /sys/arch/amd64
$ cat <<EOF >conf/SYZKALLER
include "arch/amd64/conf/GENERIC"
pseudo-device kcov 1
EOF
$ cp -R compile/GENERIC compile/SYZKALLER
$ make -C compile/SYZKALLER obj
$ make -C compile/SYZKALLER config
$ make -C compile/SYZKALLER
```

## Create VM

1. [vmd(8)](https://man.openbsd.org/vmd.8)
   must be configured to allow non-root users to create VMs since it removes the
   need to run syzkaller as root:

   ```sh
   $ cat /etc/vm.conf
   vm "syzkaller" {
     disable
     disk "/dev/null"
     local interface
     owner $USER
     allow instance { boot, disk, memory }
   }
   ```

2. Create disk image:

   ```sh
   $ vmctl create -s 4G "qcow2:$VMIMG"
   ```

3. Install VM:

   ```sh
   $ vmctl start -c -t syzkaller -b /bsd.rd -d "$VMIMG" syzkaller-1
   ```

   Answers to questions that deviates from the defaults:

   ```
   Password for root account? ******
   Allow root ssh login? yes
   ```

4. Restart the newly created VM and copy the SSH-key:

   ```sh
   $ vmctl stop -w syzkaller-1
   $ vmctl start -c -t syzkaller -d "$VMIMG" syzkaller-1
   $ ssh "root@100.64.${VMID}.3" 'cat >~/.ssh/authorized_keys' <$SSHKEY.pub
   ```

5. Optionally, library ASLR can be disabled in order to improve boot time:

   ```sh
   $ ssh "root@100.64.${VMID}.3" 'echo library_aslr=NO >>/etc/rc.conf.local'
   ```

6. Finally, stop the VM:

   ```sh
   $ vmctl stop -w syzkaller-1
   ```

## Configure and run syzkaller

```sh
$ pwd
~/go/src/github.com/google/syzkaller
$ cat openbsd.cfg
{
  "name": "openbsd",
  "target": "openbsd/amd64",
  "http": ":10000",
  "workdir": "$HOME/go/src/github.com/google/syzkaller/workdir",
  "kernel_obj": "/sys/arch/amd64/compile/SYZKALLER/obj",
  "kernel_src": "/",
  "syzkaller": "$HOME/go/src/github.com/google/syzkaller",
  "image": "$VMIMG",
  "sshkey": "$SSHKEY",
  "sandbox": "none",
  "procs": 2,
  "type": "vmm",
  "vm": {
    "count": 4,
    "mem": 512,
    "kernel": "$KERNEL",
    "template": "syzkaller"
  }
}
$ ./bin/syz-manager -config openbsd.cfg
```
