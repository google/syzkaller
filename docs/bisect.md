# Syz-bisect

`syz-bisect` program can be used to bisect culprit and fix commits for
crashes found by syzkaller. It can also identify configuration options
that are triggers for the crash.

## Usage

Build `syz-bisect` with `make bisect`.

During bisection different compilers depending on kernel revision are
used. These compilers are available
[here](https://storage.googleapis.com/syzkaller/bisect_bin.tar.gz).

Install ccache to speed up kernel compilations during bisecton.

Create user-space (chroot) using [create-image.sh](../tools/create-image.sh)

Create a config file with following lines adjusted for your environment:

```
{
	"bin_dir": "/home/syzkaller/bisect_bin",
	"ccache": "/usr/bin/ccache",
	"kernel_repo": "git://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git",
	"kernel_branch": "master",
	"syzkaller_repo": "https://github.com/google/syzkaller",
	"userspace": "/home/syzkaller/image/chroot",
	"kernel_config": "/home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream-apparmor-kasan.config",
	"kernel_baseline_config": "/home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream-apparmor-kasan-base.config",
	"syzctl": /home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream.sysctl,
	"cmdline": /home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream.cmdline,
	"manager":
	{
		"name" : "bisect",
		"target": "linux/amd64",
		"http": "127.0.0.1:56741",
		"workdir": "/home/syzkaller/workdir",
		"kernel_obj": "/home/syzkaller/linux",
		"image": "/home/syzkaller/workdir/image/image",
		"sshkey": "/home/syzkaller/workdir/image/key",
		"syzkaller": "/home/syzkaller/go/src/github.com/google/syzkaller_bisect",
		"procs": 8,
		"type": "qemu",
		"kernel_src": "/syzkaller/linux",
		"vm": {
		      "count": 4,
		      "kernel": "/home/syzkaller/linux/arch/x86/boot/bzImage",
		      "cpu": 2,
		      "mem": 2048,
		      "cmdline": "root=/dev/sda1 rw console=ttyS0 kaslr crashkernel=512M minnowboard_1:eth0::: security=none"
		}
	}
}
```

And run bisection with `bin/syz-bisect -config vm_bisect.cfg -crash
/syzkaller/workdir/crashes/03ee30ae11dfd0ddd062af26566c34a8c853698d`.

`Syz-bisect` is expecting finding repro.cprog or repro.prog in given
crash directory. It will also utilize repro.opts, but it's not
mandatory.

## Additional Arguments

`-syzkaller_commit` use this if you want to use specific version of syzkaller

`-kernel_commit` kernel commit where crash is known to reproduce. You
want to use this when bisecting fixing commit

`-fix` use this if you want to bisect a fixing commit.

## Output

It takes some time, but after `syz-bisect` completes it dumps out it's
results into console It also stores results into files in given crash
directory:

`cause.commit` commit identified causing the crash or text "the crash
already happened on the oldest tested release"

`fix.commit` commit identified fixing the crash or text "the crash
still happens on HEAD"

`cause.config` config options identified working as one trigger for the crash

`original.config, baseline.config, minimized.config` config files used
in config bisection
