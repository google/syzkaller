# Setup: Ubuntu host, QEMU vm, x86-64 kernel

These are the instructions on how to fuzz the x86-64 kernel in a QEMU with Ubuntu 14.04 on the host machine and Debian Stretch in the QEMU instances.

## GCC

Since syzkaller requires coverage support in GCC, we need to use a recent GCC version. To checkout GCC 7.1.0 sources to `$GCC` dir:
``` bash
svn checkout svn://gcc.gnu.org/svn/gcc/trunk $GCC
cd $GCC
svn ls -v ^/tags | grep gcc_7_1_0_release
svn up -r 247494
```

Unfortunately there's a typo in the source of `gcc_7_1_0_release`. Apply [this fix](https://patchwork.ozlabs.org/patch/757421/):
``` c
diff --git a/gcc/tree.h b/gcc/tree.h
index 3bca90a..fdaa7af 100644
--- a/gcc/tree.h
+++ b/gcc/tree.h
@@ -897,8 +897,8 @@  extern void omp_clause_range_check_failed (const_tree, const char *, int,
 /* If this is true, we should insert a __cilk_detach call just before
    this function call.  */
 #define EXPR_CILK_SPAWN(NODE) \
-  (tree_check2 (NODE, __FILE__, __LINE__, __FUNCTION__, \
-                CALL_EXPR, AGGR_INIT_EXPR)->base.u.bits.unsigned_flag)
+  (TREE_CHECK2 (NODE, CALL_EXPR, \
+                AGGR_INIT_EXPR)->base.u.bits.unsigned_flag)
 
 /* In a RESULT_DECL, PARM_DECL and VAR_DECL, means that it is
    passed by invisible reference (and the TREE_TYPE is a pointer to the true
```

Install GCC prerequisites:
```
sudo apt-get install flex bison libc6-dev libc6-dev-i386 linux-libc-dev linux-libc-dev:i386 libgmp3-dev libmpfr-dev libmpc-dev build-essential bc
```

Build GCC:
``` bash
mkdir build
mkdir install
cd build/
../configure --enable-languages=c,c++ --disable-bootstrap --enable-checking=no --with-gnu-as --with-gnu-ld --with-ld=/usr/bin/ld.bfd --disable-multilib --prefix=$GCC/install/
make -j64
make install
```

Now you should have GCC binaries in `$GCC/install/bin/`:
``` bash
$ ls $GCC/install/bin/
c++  gcc-ar      gcov-tool                x86_64-pc-linux-gnu-gcc-7.0.0
cpp  gcc-nm      x86_64-pc-linux-gnu-c++  x86_64-pc-linux-gnu-gcc-ar
g++  gcc-ranlib  x86_64-pc-linux-gnu-g++  x86_64-pc-linux-gnu-gcc-nm
gcc  gcov        x86_64-pc-linux-gnu-gcc  x86_64-pc-linux-gnu-gcc-ranlib
```

## Kernel

Checkout Linux kernel source:
``` bash
git clone https://github.com/torvalds/linux.git $KERNEL
```

Generate default configs:
``` bash
cd $KERNEL
make defconfig
make kvmconfig
```

Now we need to enable some config options required for syzkaller.
Edit `.config` file manually and enable:
```
CONFIG_KCOV=y
CONFIG_DEBUG_INFO=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
```

You may also need the following for a recent linux image:
```
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

You might also want to enable some other kernel configs as described [here](kernel_configs.md).

Since enabling these options results in more sub options being available, we need to regenerate config. Run this and press enter each time when prompted for some config value to leave it as default:
``` bash
make oldconfig
```

Build the kernel with previously built GCC:
```
make CC="$GCC/install/bin/gcc" -j64
```

Now you should have `vmlinux` (kernel binary) and `bzImage` (packed kernel image):
``` bash
$ ls $KERNEL/vmlinux
$KERNEL/vmlinux
$ ls $KERNEL/arch/x86/boot/bzImage 
$KERNEL/arch/x86/boot/bzImage
```

## Image

Install debootstrap:
``` bash
sudo apt-get install debootstrap
```

Create a Debian-stretch Linux image:
```
cd $IMAGE/
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

By default, this script will create a minimal Debian-stretch Linux image. The result should be `$IMAGE/stretch.img` disk image.

If you would like to generate wheezy debian image, instead of stretch, just add one option of the script
``` bash
./create-image.sh --distribution wheezy
```

Sometimes it's useful to have some additional packages and tools available in the VM even though they are not required to run syzkaller.
The instructions to install some useful tools are below.

To install other packages, like `make sysbench git vim tmux usbutils` (not required to run syzkaller):
``` bash
./create-image.sh --feature full
```

To install perf (not required to run syzkaller):
``` bash
./create-image.sh --add-perf
```
Note: remember to set `$KERNEL` before installing perf

For additional options of `create-image.sh`, please refer to `./create-image.sh -h`

## QEMU

Install `QEMU`:
``` bash
sudo apt-get install qemu-system-x86
```

Make sure the kernel boots and `sshd` starts:
``` bash
qemu-system-x86_64 \
  -kernel $KERNEL/arch/x86/boot/bzImage \
  -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ"\
  -hda $IMAGE/stretch.img \
  -net user,hostfwd=tcp::10021-:22 -net nic \
  -enable-kvm \
  -nographic \
  -m 2G \
  -smp 2 \
  -pidfile vm.pid \
  2>&1 | tee vm.log
```

```
early console in setup code
early console in extract_kernel
input_data: 0x0000000005d9e276
input_len: 0x0000000001da5af3
output: 0x0000000001000000
output_len: 0x00000000058799f8
kernel_total_size: 0x0000000006b63000

Decompressing Linux... Parsing ELF... done.
Booting the kernel.
[    0.000000] Linux version 4.12.0-rc3+ ...
[    0.000000] Command line: console=ttyS0 root=/dev/sda debug earlyprintk=serial
...
[ ok ] Starting enhanced syslogd: rsyslogd.
[ ok ] Starting periodic command scheduler: cron.
[ ok ] Starting OpenBSD Secure Shell server: sshd.
```

After that you should be able to ssh to QEMU instance in another terminal:
``` bash
ssh -i $IMAGE/stretch.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost
```

If this fails with "too many tries", ssh may be passing default keys before
the one explicitly passed with `-i`. Append option `-o "IdentitiesOnly yes"`.

To kill the running QEMU instance:
``` bash
kill $(cat vm.pid)
```

## syzkaller

Create a manager config like the following, replacing the environment
variables `$GOPATH`, `$KERNEL` and `$IMAGE` with their actual values.
```
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
	"kernel_obj": "$KERNEL",
	"image": "$IMAGE/stretch.img",
	"sshkey": "$IMAGE/stretch.id_rsa",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 4,
		"kernel": "$KERNEL/arch/x86/boot/bzImage",
		"cpu": 2,
		"mem": 2048
	}
}
```

Run syzkaller manager:
``` bash
mkdir workdir
./bin/syz-manager -config=my.cfg
```

Now syzkaller should be running, you can check manager status with your web browser at `127.0.0.1:56741`.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
