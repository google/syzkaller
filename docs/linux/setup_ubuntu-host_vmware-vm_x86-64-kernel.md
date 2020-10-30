# Setup: Ubuntu host, VMware vm, x86-64 kernel

These are the instructions on how to fuzz the x86-64 kernel in VMware Workstation with Ubuntu on the host machine and Debian Stretch in the virtual machines.

In the instructions below, the `$VAR` notation (e.g. `$GCC`, `$KERNEL`, etc.) is used to denote paths to directories that are either created when executing the instructions (e.g. when unpacking GCC archive, a directory will be created), or that you have to create yourself before running the instructions. Substitute the values for those variables manually.

## GCC and Kernel

You can follow the same [instructions](/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) for obtaining GCC and building the Linux kernel as when using QEMU.

## Image

Install debootstrap:

``` bash
sudo apt-get install debootstrap
```

To create a Debian Stretch Linux user space in the $USERSPACE dir do:
```
mkdir -p $USERSPACE
sudo debootstrap --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,open-vm-tools --components=main,contrib,non-free stretch $USERSPACE
```

Note: it is important to include the `open-vm-tools` package in the user space as it provides better VM management.

To create a Debian Stretch Linux VMDK do:

```
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-gce-image.sh -O create-gce-image.sh
chmod +x create-gce-image.sh
./create-gce-image.sh $USERSPACE $KERNEL/arch/x86/boot/bzImage
qemu-img convert disk.raw -O vmdk disk.vmdk
```

The result should be `disk.vmdk` for the disk image and `key` for the root SSH key. You can delete `disk.raw` if you want.

## VMware Workstation

Open VMware Workstation and start the New Virtual Machine Wizard.
Assuming you want to create the new VM in `$VMPATH`, complete the wizard as follows:

* Virtual Machine Configuration: Custom (advanced)
* Hardware compatibility: select the latest version
* Guest OS: select "I will install the operating system later"
* Guest OS type: Linux
* Virtual Machine Name and Location: select `$VMPATH` as location and "debian" as name
* Processors and Memory: select as appropriate
* Network connection: Use host-only networking
* I/O Controller Type: LSI Logic
* Virtual Disk Type: IDE
* Disk: select "Use an existing virtual disk"
* Existing Disk File: enter the path of `disk.vmdk` created above
* Select "Cusomize Hardware..." and remove the "Printer" device if you have one. Add a new "Serial Port" device. For the serial port connection choose "Use socket (named pipe)" and enter "serial" for the socket path. At the end it should look like this:

![Virtual Machine Settings](vmw-settings.png?raw=true)

When you complete the wizard, you should have `$VMPATH/debian.vmx`. From this point onward, you no longer need the Workstation UI.

Starting the Debian VM (headless):
``` bash
vmrun start $VMPATH/debian.vmx nogui
```

Getting the IP address of the Debian VM:
``` bash
vmrun getGuestIPAddress $VMPATH/debian.vmx -wait
```

SSH into the VM:
``` bash
ssh -i key root@<vm-ip-address>
```

Connecting to the serial port of the VM (after it is started):
``` bash
nc -U $VMPATH/serial
```

Stopping the VM:
``` bash
vmrun stop $VMPATH/debian.vmx
```

If all of the above `vmrun` commands work, then you can proceed to running syzkaller.

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
	"type": "vmware",
	"vm": {
		"count": 4,
		"base_vmx": "$VMPATH/debian.vmx",
	}
}
```

Run syzkaller manager:

``` bash
mkdir workdir
./bin/syz-manager -config=my.cfg
```

Syzkaller will create full clone VMs from the `base_vmx` VM and then use ssh to copy and execute programs in them.
The `base_vmx` VM will not be started and its disk will remain unmodified.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
