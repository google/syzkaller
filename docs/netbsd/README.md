# NetBSD

Instructions to set up syzkaller for a Linux Host and an amd64 NetBSD kernel. 

## Setup the NetBSD sources

1. Get the NetBSD kernel source (preferably HEAD).
	```sh
	$ mdkir $HOME/netbsd
	$ cd $HOME/netbsd
	$ git clone https://github.com/NetBSD/src.git
	```

2. Build the tools (You will have the toolchain in $HOME/netbsd/tools)
	```sh
	$ cd src
	$ ./build.sh -m amd64 -U -T ../tools tools
	```

3. Build the Distribution (This might take a while)
	```sh
	$ ./build.sh -m amd64 -U -T ../tools -D ../dest distribution 
	```	

At this point you should have a NetBSD distribution at `$HOME/netbsd/dest`.

## Installing and building Syzkaller on Linux Host
	
1. Install all the dependencies for Syzkaller (Go distribution can be downloaded from https://golang.org/dl/)

2. Clone the Syzkaller Repository
	```sh
	$ go get -u -d github.com/google/syzkaller/.. 
	$ cd ~/go/src/github.com/google/syzkaller
	```

3. Compile Syzkaller for NetBSD  
	```sh
	$ make TARGETOS=netbsd SOURCEDIR=$HOME/netbsd/src
	```

The above steps should have built the Syzkaller binaries for NetBSD. 

You can see the compiled binaries in `bin/netbsd_amd64`.


## Setting up a NetBSD VM with qemu 

Please follow the tutorial given [here](https://wiki.qemu.org/Hosts/BSD#NetBSD) to
setup a basic NetBSD VM with qemu.

After installing and running the NetBSD VM on qemu please follow the steps below to
configure ssh.

1. Create a ssh-keypair on the host and save it as `netbsdkey`.
	```sh
	$ ssh-keygen -t rsa
	```

2. Append the following lines to `/etc/rc.conf` on the guest. (use `vi` editor)
	```
	sshd=YES
	dhcpcd=YES
	ifconfig_wm0="inet 10.0.2.15 netmask 255.255.255.0"
	```
	
3. Append this to `/etc/ssh/sshd_config` on the guest.
	```
	Port 22
	ListenAddress 10.0.2.15
	PermitRootLogin yes
	PermitRootLogin without-password
	```

4. Now you should be able to ssh into the netbsd VM.
	```sh
	$ ssh -p 10022 root@127.0.0.1
	```

5. Copy and paste your public key to `/root/.ssh/authorized_keys` on the guest 
   and `reboot` the VM.
 
6. After reboot make sure that the ssh is working properly. Replace the port with what
   you have configured. 
	```sh
	$ ssh -i path/to/netbsdkey -p 10022 root@127.0.0.1
	```

If the last command returns a proper shell it means the VM has been configured.


## Compiling a NetBSD kernel (Optional)

You can compile a kernel with KASAN to increase the chances of finding bugs.

1. Make a copy of the config file
	```sh
	$ cd $HOME/netbsd/src
	$ cp sys/arch/amd64/conf/GENERIC sys/arch/amd64/conf/SYZKALLER 
	```

2. Uncomment the following lines in `sys/arch/amd64/conf/SYZKALLER` to enable KASAN
	```
	#makeoptions 	KASAN=1		# Kernel Address Sanitizer
	#options 	KASAN
	#no options	SVS
	```

3. Compile the kernel with KASAN (Assuming you have followed the inital steps to
   build tools)
	```sh
	$ cd $HOME/netbsd/src
	$ ./build.sh -m amd64 -U -T ../tools -j4 kernel=SYZKALLER

	```

4. At this point you should have the new compiled kernel image which can be found in 
   `$HOME/netbsd/src/sys/arch/amd64/compile/SYZKALLER` and should have the name 
   `netbsd`. You need to copy it to the installed VM and reboot the VM.

## Running Syzkaller

1. If all of the above worked, `poweroff` the VM and create `netbsd.cfg` config file with the following contents (alter paths as necessary):
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

(Above directories have to be specified to the exact locations and the ssh keys must be in a separate directory with chmod 700 permissions set to that directory and chmod 600 permissions to the files in both the guest and the host.)


2. Then, start `syz-manager` with: (Inside the syzkaller folder where the netbsd.cfg file also exists)
	```sh
	$ bin/syz-manager -config netbsd.cfg
	```

(You can add a `-debug` flag to the above command to view the log if any issues arise.)

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

## Missing things

- Automating the configuation changes (like appending to config files), generating the json config file on the fly (with customizable values to the keys using command line parameters) and calling syz-manager with `anita` using just a single command.
- Coverage. `executor/executor_netbsd.cc` uses a very primitive fallback for coverage. We need KCOV for NetBSD. It will also help to assess what's covered and what's missing.
- System call descriptions. `sys/netbsd/*.txt` is a dirty copy from `sys/linux/*.txt` with everything that does not compile dropped. We need to go through syscalls and verify/fix/extend them, including devices/ioctls/etc.
- Currently only `amd64` arch is supported. Supporting `386` would be useful, because it should cover compat paths. Also, we could do testing of the linux-compatibility subsystem.
- `pkg/csource` needs to be taught how to generate/build C reproducers.
- `pkg/host` needs to be taught how to detect supported syscalls/devices.
- `pkg/report`/`pkg/symbolizer` need to be taught how to extract/symbolize kernel crash reports.
- We need to learn how to build/use debug version of kernel.
- On Linux we have emission of exernal networking/USB traffic into kernel using tun/gadgetfs. Implementing these for NetBSD could uncover a number of high-profile bugs.
- Last but not least, we need to support NetBSD in `syz-ci` command (including building kernel/image continuously from git).
