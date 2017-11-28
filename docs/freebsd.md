# FreeBSD

## How to run syzkaller on FreeBSD using qemu

So far the process is tested only on linux/amd64 host. To build Go binaries do:
```
make manager fuzzer execprog TARGETOS=freebsd
```
To build C `syz-executor` binary, copy `executor/*` files to a FreeBSD machine and build there with:
```
c++ executor/executor_freebsd.cc -o syz-executor -O1 -lpthread -DGOOS=\"freebsd\" -DGIT_REVISION=\"CURRENT_GIT_REVISION\"
```
Then, copy out the binary back to host into `bin/freebsd_amd64` dir.

Building/running on a FreeBSD host should work as well, but currently our `Makefile` does not work there, so you will need to do its work manually.

Then, you need a FreeBSD image with root ssh access with a key. General instructions can be found here [qemu instructions](https://wiki.qemu.org/Hosts/BSD). I used `FreeBSD-11.0-RELEASE-amd64.qcow2` image, and it required a freashly built `qemu-system-x86_64` (networking did not work in the system-provided one). After booting add the following to `/boot/loader.conf`:
```
autoboot_delay="-1"
console="comconsole"
```
and the following to `/etc/rc.conf`:
```
sshd_enable="YES"
ifconfig_em0="inet 10.0.0.1 netmask 255.255.255.0"
```
Here is `/etc/ssh/sshd_config` that I used:
```
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
SyslogFacility AUTH
LogLevel INFO
AuthenticationMethods publickey password
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
PasswordAuthentication yes
PermitEmptyPasswords yes
Subsystem sftp /usr/libexec/sftp-server
```

Check that you can run the VM with:
```
qemu-system-x86_64 -m 2048 -hda FreeBSD-11.0-RELEASE-amd64.qcow2 -enable-kvm -netdev user,id=mynet0,host=10.0.2.10,hostfwd=tcp::10022-:22 -device e1000,netdev=mynet0 -nographic
```
and ssh into it with a key.

If all of the above worked, create `freebsd.cfg` config file with the following contents (alter paths as necessary):
```
{
	"name": "freebsd",
	"target": "freebsd/amd64",
	"http": ":10000",
	"workdir": "/workdir",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"image": "/FreeBSD-11.1-RELEASE-amd64.qcow2",
	"sshkey": "/freebsd_id_rsa",
	"sandbox": "none",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"qemu": "/qemu/build/x86_64-softmmu/qemu-system-x86_64",
		"count": 10,
		"cpu": 4,
		"mem": 2048
	}
}
```

Then, start `syz-manager` with:
```
bin/syz-manager -config freebsd.cfg
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

- Coverage. `executor/executor_freebsd.cc` uses a very primitive fallback for coverage. We need KCOV for FreeBSD. It will also help to assess what's covered and what's missing.
- System call descriptions. `sys/freebsd/*.txt` is a dirty copy from `sys/linux/*.txt` with everything that does not compile dropped. We need to go through syscalls and verify/fix/extend them, including devices/ioctls/etc.
- Currently only `amd64` arch is supported. Supporting `386` would be useful, because it should cover compat paths. Also, we could do testing of the linux-compatibility subsystem.
- `pkg/csource` needs to be taught how to generate/build C reproducers.
- `pkg/host` needs to be taught how to detect supported syscalls/devices.
- `pkg/report`/`pkg/symbolizer` need to be taught how to extract/symbolize kernel crash reports.
- We need to learn how to build/use debug version of kernel.
- KASAN for FreeBSD would be useful.
- On Linux we have emission of exernal networking/USB traffic into kernel using tun/gadgetfs. Implementing these for FreeBSD could uncover a number of high-profile bugs.
- Last but not least, we need to support FreeBSD in `syz-ci` command (including building kernel/image continuously from git).
