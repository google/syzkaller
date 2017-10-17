# FreeBSD

To setup a VM follow the [qemu instructions](https://wiki.qemu.org/Hosts/BSD).
Start a VM with:
```
qemu-system-x86_64 -m 2048 -hda FreeBSD-11.0-RELEASE-amd64.qcow2 -enable-kvm -netdev user,id=mynet0,host=10.0.2.10,hostfwd=tcp::10022-:22 -device e1000,netdev=mynet0 -nographic
```
(for me it required building a fresh qemu-system-x86_64)

After booting add the following to `/boot/loader.conf`:
```
autoboot_delay="-1"
console="comconsole"
```

and the following to `/etc/rc.conf`:
```
sshd_enable="YES"
ifconfig_em0="inet 10.0.0.1 netmask 255.255.255.0"
```

setup sshd in `/etc/ssh/sshd_config` along the lines of:
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
