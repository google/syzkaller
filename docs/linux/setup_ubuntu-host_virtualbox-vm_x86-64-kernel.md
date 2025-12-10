# Setup: Ubuntu host, VirtualBox vm, x86-64 kernel

These are the instructions on how to fuzz the x86-64 kernel in VirtualBox with Ubuntu on the host machine and Debian Trixie in the virtual machines.

In the instructions below, the `$VAR` notation (e.g. `$GCC`, `$KERNEL`, etc.) is used to denote paths to directories that are either created when executing the instructions (e.g. when unpacking GCC archive, a directory will be created), or that you have to create yourself before running the instructions. Substitute the values for those variables manually.

## GCC and Kernel

You can follow the same [instructions](/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) for obtaining GCC and building the Linux kernel as when using QEMU.

## Image

Install debootstrap:

``` bash
sudo apt-get install debootstrap
```

To create a Debian Trixie Linux user space in the $USERSPACE dir do:
```
sudo mkdir -p $USERSPACE
sudo debootstrap --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,open-vm-tools --components=main,contrib,non-free trixie $USERSPACE
```

Note: it is important to include the `open-vm-tools` package in the user space as it provides better VM management.

To create a Debian Trixie Linux VMDK do:

```
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-gce-image.sh -O create-gce-image.sh
chmod +x create-gce-image.sh
./create-gce-image.sh $USERSPACE $KERNEL/arch/x86/boot/bzImage
qemu-img convert -f raw -O vdi disk.raw disk.vdi
```

The result should be `disk.vdi` for the disk image. You can delete `disk.raw` if you want.

## VirtualBox

Open VirtualBox and start the New Virtual Machine Wizard.
Assuming you want to create the new VM in `$VMPATH`, complete the wizard as follows:

* Create New Virtual Machine
* Virtual Machine Name and Location: select `$VMPATH` as location and "debian" as name
* Guest OS type: Debian 64-bit
* Disk: select "Use an existing virtual disk"
* Import the `disk.vdi` file, and select the imported `.vdi` file as an Hard Disk File.

When you complete the wizard, you should have `$VMPATH/debian.vbox`. From this point onward, you no longer need the VirtualBox UI.

To test the fuzzing environment before getting started, follow the instructions below:
Forwarding port 2222 on your host machine to port 22:
``` bash
VBoxManage modifyvm debian --natpf1 "test,tcp,,2222,,22"
```

Starting the Debian VM (headless):
``` bash
VBoxManage startvm debian --type headless
```

SSH into the VM:
``` bash
ssh -p 2222 root@127.0.0.1
```

Stopping the VM:
``` bash
VBoxManage controlvm debian poweroff
```

If all of the above `VBoxManage` commands work, then you can proceed to running syzkaller.

## syzkaller

Create a manager config like the following, replacing the environment variables $GOPATH, $KERNEL and $VMPATH with their actual values.

```
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
    "kernel_obj": "$KERNEL",
    "sshkey": "$IMAGE/key",
    "syzkaller": "$GOPATH/src/github.com/google/syzkaller",
    "procs": 8,
    "type": "virtualbox",
    "vm": {
        "count": 4,
        "base_vm_name": "debian"
    }
}
```

Run syzkaller manager:

``` bash
mkdir workdir
./bin/syz-manager -config=my.cfg
```

Syzkaller will create full clone VMs from the `debian` VM and then use ssh to copy and execute programs in them.
The `debian` VM will not be started and its disk will remain unmodified.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
