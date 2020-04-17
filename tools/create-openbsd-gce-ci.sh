#!/bin/bash

# Copyright 2018 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Produces GCE image of syz-ci running on OpenBSD.

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
cat >install.site <<EOF
#!/bin/sh
PKGS="bash gcc%8 git gmake go llvm nano wget"
PKG_PATH=https://${MIRROR}/pub/OpenBSD/${DOWNLOAD_VERSION}/packages/${ARCH}/ pkg_add -I \$PKGS
PKG_PATH= pkg_info -I \$PKGS && echo pkg_add OK

echo 'set tty com0' > boot.conf
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'pass in on egress proto tcp from any to any port 80 rdr-to 127.0.0.1 port 8080' >> /etc/pf.conf
echo 'permit keepenv nopass syzkaller as root' > /etc/doas.conf

mkdir /syzkaller
echo '/dev/sd1a /syzkaller ffs rw,noauto 1 0' >> /etc/fstab
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
  set -eux

  echo "starting syz-ci"
  fsck -y /dev/sd1a
  mount /syzkaller
  su -l syzkaller <<EOF2
    cd /syzkaller
    set -eux
    ulimit -d 8000000
    test -x syz-ci || (
         go get github.com/google/syzkaller/syz-ci &&
         go build github.com/google/syzkaller/syz-ci)
    ./syz-ci -config ./config-openbsd.ci 2>&1 | tee syz-ci.log &
EOF2
)
EOF
chmod +x install.site

cat >etc/rc.conf.local <<EOF
slaacd_flags=NO
smtpd_flags=NO
sndiod_flags=NO
EOF

cat >etc/sysctl.conf <<EOF
hw.smt=1
EOF

tar --owner=root --group=root -zcvf site${RELNO}.tgz install.site etc/*

# Autoinstall script.
cat >auto_install.conf <<EOF
System hostname = ci-openbsd
DNS domain name = syzkaller
Which network interface = vio0
IPv4 address for vio0 = dhcp
IPv6 address for vio0 = none
Password for root account = root
Public ssh key for root account = ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJeLpmSq+Dgrk01Ht+QtY0GDsY2gcwhT12SqizmacAF67TCa0n8OcpjVOpiiurb01Aa5lcl2WbakUFYmsp1U1l8=
Do you expect to run the X Window System = no
Change the default console to com0 = yes
Which speed should com0 use = 115200
Setup a user = syzkaller
Full name for user syzkaller = Syz Kaller
Password for user syzkaller = syzkaller
Public ssh key for user syzkaller = ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJeLpmSq+Dgrk01Ht+QtY0GDsY2gcwhT12SqizmacAF67TCa0n8OcpjVOpiiurb01Aa5lcl2WbakUFYmsp1U1l8=
Allow root ssh login = prohibit-password
What timezone = US/Pacific
Which disk = sd0
Use (W)hole disk or (E)dit the MBR = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = auto
URL to autopartitioning template for disklabel = file:/disklabel.template
Set name(s) = +* -x* -game* done
Directory does not contain SHA256.sig. Continue without verification = yes
Location of sets = cd0
EOF

# Disklabel template.
cat >disklabel.template <<EOF
/	5G-*	95%
swap	1G
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
rm -f disk.raw
qemu-img create -f raw disk.raw 10G

# Run the installer to create the disk image.
expect 2>&1 <<EOF | tee install_log
set timeout 1800

spawn qemu-system-x86_64 -nographic -smp 2 \
  -drive if=virtio,file=disk.raw,format=raw -cdrom "${ISO_PATCHED}" \
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

grep 'pkg_add OK' install_log > /dev/null \
    || { echo Package installation failed. Inspect install_log. 2>&1 ; exit 1; }

# Create Compute Engine disk image.
echo "Archiving disk.raw... (this may take a while)"
i="openbsd-${ARCH}-${RELNO}-gce.tar.gz"
tar -Szcf "$i" disk.raw

cat <<EOF
Done.

To create GCE image run the following commands:

gsutil cp -a public-read "$i" gs://syzkaller/
gcloud compute images create ci-openbsd-root --source-uri gs://syzkaller/"$i"

EOF
