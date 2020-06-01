# NetBSD

Instructions to set up syzkaller for a Linux host and a NetBSD guest.

## Preparing the NetBSD sources

1. Get the NetBSD kernel source (preferably HEAD).
	```sh
	host$ mdkir $HOME/netbsd
	host$ cd $HOME/netbsd
	host$ git clone https://github.com/NetBSD/src.git
	```

2. Build the tools. You will have the toolchain in `$HOME/netbsd/tools`.
	```sh
	host$ cd src
	host$ ./build.sh -j4 -m amd64 -U -T ../tools tools
	```

3. Build the distribution. This might take a while.
	```sh
	host$ ./build.sh -j4 -m amd64 -U -T ../tools -D ../dest distribution
	```

At this point you should have a NetBSD distribution in `$HOME/netbsd/dest`.

## Installing and building syzkaller on the Linux host

1. Install all the dependencies for syzkaller.

2. Clone the syzkaller repository.
	```sh
	host$ go get -u -d github.com/google/syzkaller/prog
	host$ cd ~/go/src/github.com/google/syzkaller
	```

3. Compile syzkaller for NetBSD.
	```sh
	host$ make TARGETOS=netbsd SOURCEDIR=$HOME/netbsd
	```

The above steps should have built the syzkaller binaries for NetBSD.

You can see the compiled binaries in `bin/netbsd_amd64`.

## Setting up a NetBSD VM with qemu

You can use the script given [here](https://github.com/R3x/netbsd-fuzzing-aids/blob/master/install_netbsd.sh) to create a disk image with NetBSD installed.
The script would also automatically give you a ssh key to ssh into the VM.

Alternatively, you can follow the tutorial given [here](https://wiki.qemu.org/Hosts/BSD#NetBSD) to
set up a basic NetBSD VM with qemu.

After installing and running the NetBSD VM on qemu, please follow the steps below to
configure ssh.

1. Create a ssh-keypair on the host and save it as `netbsdkey`.
	```sh
	host$ ssh-keygen -f netbsdkey -t rsa -N ""
	```

2. Make sure you have a NAT enabled in your Qemu command line. Typically to
   forward the host port `10022` to the guest port `22`:
	```sh
	host$ qemu-system-x86_64 ... -netdev user,id=mynet0,hostfwd=tcp:127.0.0.1:10022-:22 -device e1000,netdev=mynet0
	```

3. Append the following lines to `/etc/rc.conf` on the guest. You can use the `vi` editor to do that.
	```
	sshd=YES
	dhcpcd=YES
	ifconfig_wm0="inet 10.0.2.15 netmask 255.255.255.0"
	```

4. Append this to `/etc/ssh/sshd_config` on the guest.
	```
	Port 22
	ListenAddress 10.0.2.15
	PermitRootLogin yes
	PermitRootLogin without-password
	```

5. Now you should be able to ssh into the NetBSD VM.
	```sh
	host$ ssh -p 10022 root@127.0.0.1
	```

6. Copy and paste your public key to `/root/.ssh/authorized_keys` on the guest
   and `reboot` the VM.

7. After reboot make sure that ssh is working properly. Replace the port with what
   you have configured.
	```sh
	host$ ssh -i path/to/netbsdkey -p 10022 root@127.0.0.1
	```

If the last command returns a proper shell it means the VM has been configured.

## Compiling a NetBSD kernel (Optional)

You can compile a kernel with KASAN to increase the chances of finding bugs.

1. Make a copy of the config file.
	```sh
	host$ cd $HOME/netbsd/src
	host$ cp sys/arch/amd64/conf/GENERIC sys/arch/amd64/conf/SYZKALLER
	```

2. Uncomment the following lines in `sys/arch/amd64/conf/SYZKALLER` to enable KASAN.
	```
	#makeoptions 	KASAN=1		# Kernel Address Sanitizer
	#options 	KASAN
	#no options	SVS
	```

3. Compile the kernel with KASAN (assuming you have followed the initial steps to
   build tools).
	```sh
	host$ cd $HOME/netbsd/src
	host$ ./build.sh -m amd64 -U -T ../tools -j4 kernel=SYZKALLER
	```

4. At this point you should have the new compiled kernel image which can be found in
   `$HOME/netbsd/src/sys/arch/amd64/compile/SYZKALLER` and should have the name
   `netbsd`. You need to copy it to the installed VM and reboot the VM.

## Running syzkaller

1. If all of the above worked, `poweroff` the VM and create the `netbsd.cfg` config
   file on the host with the following contents (alter paths as necessary):
	```
	{
		"name": "netbsd",
		"target": "netbsd/amd64",
		"http": ":10000",
		"workdir": "work",
		"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
		"image": "path/to/netbsd.img",
		"sshkey": "/path/to/netbsdkey",
		"sandbox": "none",
		"procs": 2,
		"cover": false,
		"type": "qemu",
		"vm": {
			"qemu": "qemu-system-x86_64",
			"count": 2,
			"cpu": 2,
			"mem": 2048
		}
	}
	```
   The above directories have to be specified to the exact locations and the ssh keys
   must be in a separate directory with chmod 700 permissions set to that directory
   and chmod 600 permissions to the files in both the guest and the host.

2. Then, inside the syzkaller folder where the `netbsd.cfg` file also exists, start `syz-manager` with:
	```sh
	host$ bin/syz-manager -config netbsd.cfg
	```
   You can add a `-debug` flag to the above command to view the log if any issues arise.

3. Once syzkaller has started executing, it should start printing output along the lines of:
	```
	booting test machines...
	wait for the connection from test machine...
	machine check: 253 calls enabled, kcov=true, kleakcheck=false, faultinjection=false, comps=false
	executed 3622, cover 1219, crashes 0, repro 0
	executed 7921, cover 1239, crashes 0, repro 0
	executed 32807, cover 1244, crashes 0, repro 0
	executed 35803, cover 1248, crashes 0, repro 0
	```

## syzbot

[syzbot](/docs/syzbot.md) tests NetBSD and reports bugs to
[syzkaller-netbsd-bugs](https://groups.google.com/forum/#!forum/syzkaller-netbsd-bugs) mailing list
(also can be seen on [dashboard](https://syzkaller.appspot.com/netbsd)).

The image `syzbot` uses can be downloaded [here](https://storage.googleapis.com/syzkaller/netbsd-image.tar.gz) (266MB, includes root ssh key). The image was built using this [script](https://github.com/R3x/netbsd-fuzzing-aids/blob/master/install_netbsd.sh).

The image can be used with qemu as follows:
```
qemu-system-x86_64 -m 1024 -smp 2 -nographic -enable-kvm \
	-netdev user,id=mynet0,hostfwd=tcp:127.0.0.1:10022-:22 \
	-device e1000,netdev=mynet0 -hda netbsd-image.raw
```

And then you can ssh/scp into the VM using:
```
ssh -i netbsd-image.key -p 10022 -o IdentitiesOnly=yes root@localhost
scp -i netbsd-image.key -P 10022 -o IdentitiesOnly=yes FILE root@localhost:/root/
```

Note: the image contains a stock kernel, so if you are reproducing a bug
most likely you want to update kernel as the first step:
```
scp -i netbsd-image.key -P 10022 -o IdentitiesOnly=yes \
	src/sys/arch/amd64/compile/obj/GENERIC_SYZKALLER/netbsd root@localhost:/netbsd
ssh -i netbsd-image.key -p 10022 -o IdentitiesOnly=yes root@localhost /sbin/reboot
```

## Missing things

- Automating the configuation changes (like appending to config files), generating the json config file on the fly (with customizable values to the keys using command line parameters) and calling syz-manager with `anita` using just a single command.
- System call descriptions. `sys/netbsd/*.txt` is a dirty copy from `sys/linux/*.txt` with everything that does not compile dropped. We need to go through syscalls and verify/fix/extend them, including devices/ioctls/etc.
- Currently only `amd64` arch is supported. Supporting `386` would be useful, because it should cover compat paths. Also, we could do testing of the linux-compatibility subsystem.
- `pkg/host` needs to be taught how to detect supported syscalls/devices.
- On Linux we have emission of exernal networking/USB traffic into kernel using tun/gadgetfs. Implementing these for NetBSD could uncover a number of high-profile bugs.
