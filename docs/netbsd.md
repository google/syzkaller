# NetBSD

## How to run syzkaller on NetBSD using qemu

So far the process is tested only on linux/amd64 host. To build Go binaries do:
```
make TARGETOS=netbsd
```
To build C `syz-executor` binary, copy `executor/*` files to a NetBSD machine and build there with:
```
gcc executor/executor_NetBSD.cc -o syz-executor -O1 -lpthread -DGOOS=\"netbsd\" -DGIT_REVISION=\"CURRENT_GIT_REVISION\"
```
Then, copy out the binary back to host into `bin/netbsd_amd64` dir.

Building/running on a NetBSD host should work as well, but currently our `Makefile` does not work there, so you will need to do its work manually.

Then, you need a NetBSD image with root ssh access with a key. General instructions can be found here [qemu instructions](https://wiki.qemu.org/Hosts/BSD).

To prepare the image, use `anita`. (You need the python module `pexpect` installed, for using Anita)
```
git clone https://github.com/utkarsh009/anita
python anita/anita --workdir anitatemp install http://nycdn.netbsd.org/pub/NetBSD-daily/netbsd-8/201710221410Z/amd64/
```
NOTE: You can choose your own release tree from here: http://ftp.netbsd.org/pub/NetBSD/
URL for a daily build might not exist in future and new release trees keep coming out.

Then spin up an instance from the image generated inside `./anitatemp` directory
```
qemu-system-x86_64 -m 1024 -drive file=anitatemp/wd0.img,format=raw,media=disk -netdev user,id=mynet0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10022-:22 -device e1000,netdev=mynet0 -nographic
```
Then create an ssh-keypair without a password and save it by the name, say, `netbsdkey`

```
ssh-keygen -t rsa
```
Then append the following to `/etc/rc.conf`
```
sshd=YES
ifconfig_wm0="inet 10.0.2.15 netmask 255.255.255.0"
```
Append this to `/etc/ssh/sshd_config`
```
Port 22
ListenAddress 10.0.2.15
```
Then add your pubkey to `/root/.ssh/authorized_keys` and `reboot` the VM.
When you see the login prompt, open up another terminal on host and issue the following command
```
ssh -i netbsdkey -p 10022 root@127.0.0.1
```

If all of the above worked, `poweroff` the VM and create `netbsd.cfg` config file with the following contents (alter paths as necessary):
```
{
	"name": "netbsd",
	"target": "netbsd/amd64",
	"http": ":10000",
	"workdir": "work",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"image": "anitatemp/wd0.img",
	"sshkey": "/path/to/netbsdkey",
	"sandbox": "none",
	"procs": 2,
	"type": "qemu",
	"vm": {
		"qemu": "qemu-system-x86_64",
		"count": 2,
		"cpu": 2,
		"mem": 2048
	}
}
```

Then, start `syz-manager` with:
```
bin/syz-manager -config netbsd.cfg
```
It should start printing output along the lines of:
```
booting test machines...
wait for the connection from test machine...
machine check: 253 calls enabled, kcov=true, kleakcheck=false, faultinjection=false, comps=false
executed 3622, cover 1219, crashes 0, repro 0
executed 7921, cover 1239, crashes 0, repro 0
executed 32807, cover 1244, crashes 0, repro 0
executed 35803, cover 1248, crashes 0, repro 0
```
If something does not work, add `-debug` flag to `syz-manager`.

## Missing things

- Automating the configuation changes (like appending to config files), generating the json config file on the fly (with customizable values to the keys using command line parameters) and calling syz-manager with `anita` using just a single command.
- Coverage. `executor/executor_netbsd.cc` uses a very primitive fallback for coverage. We need KCOV for NetBSD. It will also help to assess what's covered and what's missing.
- System call descriptions. `sys/netbsd/*.txt` is a dirty copy from `sys/linux/*.txt` with everything that does not compile dropped. We need to go through syscalls and verify/fix/extend them, including devices/ioctls/etc.
- Currently only `amd64` arch is supported. Supporting `386` would be useful, because it should cover compat paths. Also, we could do testing of the linux-compatibility subsystem.
- `pkg/csource` needs to be taught how to generate/build C reproducers.
- `pkg/host` needs to be taught how to detect supported syscalls/devices.
- `pkg/report`/`pkg/symbolizer` need to be taught how to extract/symbolize kernel crash reports.
- We need to learn how to build/use debug version of kernel.
- KASAN for NetBSD would be useful.
- On Linux we have emission of exernal networking/USB traffic into kernel using tun/gadgetfs. Implementing these for NetBSD could uncover a number of high-profile bugs.
- Last but not least, we need to support NetBSD in `syz-ci` command (including building kernel/image continuously from git).
