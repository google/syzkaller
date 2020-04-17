#!/bin/bash

# Copyright 2018 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Produces a very minimal image for running syzkaller fuzzers running on OpenBSD.

# Mostly derived from Go buildlet generator with blessing from bradfitz@.

set -eu -o pipefail

readonly MIRROR="${MIRROR:-cdn.openbsd.org}"
readonly VERSION="${VERSION:-6.7}"
readonly DOWNLOAD_VERSION="${DOWNLOAD_VERSION:-snapshots}"
readonly RELNO="${2:-${VERSION/./}}"

# The only supported setting.
readonly ARCH="amd64"

readonly ISO="install${RELNO}-${ARCH}.iso"
readonly ISO_PATCHED="install${RELNO}-${ARCH}-patched.iso"

if [[ ! -f "${ISO}" ]]; then
  curl -o "${ISO}" "https://${MIRROR}/pub/OpenBSD/${DOWNLOAD_VERSION}/${ARCH}/install${RELNO}.iso"
fi

# Create custom siteXX.tgz set.
rm -fr etc && mkdir -p etc
cat >install.site <<'EOF'
#!/bin/sh
echo 'set tty com0' > boot.conf
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config

rm /usr/libexec/reorder_kernel
ln -s /usr/bin/true /usr/libexec/reorder_kernel
rm -fr /usr/share/relink

perl -i.bak -pne 's/^(ttyC.*)vt220.*/$1unknown off/' /etc/ttys

touch root/.hushlogin home/syzkaller/.hushlogin
EOF

cat >etc/sysctl.conf <<EOF
ddb.max_line=0
ddb.max_width=0
hw.smt=1
EOF

cat >etc/installurl <<EOF
https://${MIRROR}/pub/OpenBSD
EOF

cat >etc/rc.local <<EOF
(
  nc metadata.google.internal 80 <<EOF2 | tail -n1 > /etc/myname.gce \
  && echo >> /etc/myname.gce \
  && mv /etc/myname{.gce,} \
  && hostname \$(cat /etc/myname)
GET /computeMetadata/v1/instance/hostname HTTP/1.0
Host: metadata.google.internal
Metadata-Flavor: Google

EOF2
)
EOF

chmod +x install.site

cat >etc/rc.conf.local <<EOF
cron_flags=NO
pflogd_flags=NO
library_aslr=NO
slaacd_flags=NO
smtpd_flags=NO
sndiod_flags=NO
pf=NO
ntpd_flags=NO
EOF

# Generate the worker keys.
rm -f worker_key*
ssh-keygen -t ed25519 -N '' -f worker_key -C worker_key

tar --owner=root --group=root -zcvf site${RELNO}.tgz install.site etc/*

# Autoinstall script.
cat >auto_install.conf <<EOF
System hostname = worker
DNS domain name = syzkaller
Which network interface = vio0
IPv4 address for vio0 = dhcp
IPv6 address for vio0 = none
Password for root account = root
Public ssh key for root account = $(cat worker_key.pub)
Do you expect to run the X Window System = no
Change the default console to com0 = yes
Which speed should com0 use = 115200
Setup a user = syzkaller
Full name for user syzkaller = Syz Kaller
Password for user syzkaller = syzkaller
Public ssh key for user syzkaller = $(cat worker_key.pub)
Allow root ssh login = prohibit-password
What timezone = US/Pacific
Which disk = sd0
Use (W)hole disk or (E)dit the MBR = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = auto
URL to autopartitioning template for disklabel = file:/disklabel.template
Set name(s) = -* +bsd +bsd.mp +base* +site* done
Directory does not contain SHA256.sig. Continue without verification = yes
Location of sets = cd0
EOF

# Disklabel template.
cat >disklabel.template <<EOF
/	700M-*	100%
swap	300M
EOF

# Hack install CD a bit.
echo 'set tty com0' > boot.conf
dd if=/dev/urandom of=random.seed bs=4096 count=1
cp "${ISO}" "${ISO_PATCHED}"
growisofs -M "${ISO_PATCHED}" -l -R -graft-points \
  /${VERSION}/${ARCH}/site${RELNO}.tgz=site${RELNO}.tgz \
  /auto_install.conf=auto_install.conf \
  /disklabel.template=disklabel.template \
  /etc/boot.conf=boot.conf \
  /etc/random.seed=random.seed

# Initialize disk image.
rm -f worker_disk.raw
qemu-img create -f raw worker_disk.raw 1G

# Run the installer to create the disk image.
expect 2>&1 <<EOF | tee install_log
set timeout 1800

spawn qemu-system-x86_64 -nographic -smp 2 \
  -drive if=virtio,file=worker_disk.raw,format=raw -cdrom "${ISO_PATCHED}" \
  -net nic,model=virtio -net user -boot once=d -m 4000 -enable-kvm

expect timeout { exit 1 } "boot>"
send "\n"

# Need to wait for the kernel to boot.
expect timeout { exit 1 } "\(I\)nstall, \(U\)pgrade, \(A\)utoinstall or \(S\)hell\?"
send "s\n"

expect timeout { exit 1 } "# "
send "mount /dev/cd0c /mnt\n"
send "cp /mnt/auto_install.conf /mnt/disklabel.template /\n"
send "chmod a+r /disklabel.template\n"
send "umount /mnt\n"
send "exit\n"

expect timeout { exit 1 } "CONGRATULATIONS!"

proc login {} {
    send "root\n"

    expect "Password:"
    send "root\n"

    expect "# "
    send "cat /etc/ssh/ssh_host_*_key.pub\nhalt -p\n"

    expect eof
}

# There is some form of race condition with OpenBSD 6.2 MP
# and qemu, which can result in init(1) failing to run /bin/sh
# the first time around...
expect {
  timeout { exit 1 }
  "Enter pathname of shell or RETURN for sh:" {
    send "\nexit\n"
    expect "login:" {
      login
    }
  }
  "login:" {
    login
  }
}
EOF

cat <<EOF
Done: worker_disk.raw
EOF
