#!/usr/bin/env bash

# Copyright 2018 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Produces GCE image of syz-ci running on FreeBSD 15.1.  Based on create-openbsd-gce-ci.sh.

set -eux -o pipefail

readonly ARCH=amd64
readonly VERSION=15.1-RC1
readonly IMAGE="FreeBSD-${VERSION}-${ARCH}-ufs.raw.xz"

if [ "$(uname)" = FreeBSD ]; then
  readonly TAR=gtar
else
  readonly TAR=tar
fi

if [ ! -f disk.raw ]; then
  if [ ! -f $IMAGE ]; then
    curl -o $IMAGE "https://download.freebsd.org/ftp/releases/VM-IMAGES/${VERSION}/amd64/Latest/${IMAGE}"
  fi
  cp -f "$IMAGE" disk.raw.xz
  unxz disk.raw.xz
  truncate -s 20g disk.raw
fi

cat >setup.sh <<EOF
#!/bin/sh

set -e

cp -f /mnt/rc.local /etc/rc.local
mkdir -p /root/.ssh
cp -f /mnt/id_ed25519.pub /root/.ssh/authorized_keys

echo 'console=comconsole' >> /boot/loader.conf

echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'PermitRootLogin without-password' >> /etc/ssh/sshd_config
echo 'UsePAM no' >> /etc/ssh/sshd_config

echo 'hostname=ci-freebsd'
echo 'sshd_enable=YES' >> /etc/rc.conf

echo 'debug.debugger_on_panic=0' >> /etc/sysctl.conf

sed -i -e '/KEYWORD: firstboot/d' /etc/rc.d/growfs

PKGS="bash gcc git gmake go llvm wget"
for pkg in \$PKGS; do
  pkg install -y \$pkg
done

mkdir /syzkaller
EOF

cat >rc.local <<EOF
nc metadata.google.internal 80 <<EOF2 | tail -n1 > /etc/myname.gce \
  && echo >> /etc/myname.gce \
  && mv /etc/myname.gce /etc/myname \
  && hostname \$(cat /etc/myname)
GET /computeMetadata/v1/instance/hostname HTTP/1.0
Host: metadata.google.internal
Metadata-Flavor: Google

EOF2

cd /syzkaller
export HOME=/syzkaller
export PATH=${PATH}:/usr/local/sbin:/usr/local/bin
set -eux
mkdir -p /syzkaller/go-cache
export GOCACHE=/syzkaller/go-cache
test -d /syzkaller/gopath/src/github.com/google/syzkaller || (
  mkdir -p /syzkaller/gopath/src/github.com/google && \
  git clone https://github.com/google/syzkaller.git && \
  mv syzkaller /syzkaller/gopath/src/github.com/google)
(cd /syzkaller/gopath/src/github.com/google/syzkaller && \
  gmake ci && \
  install bin/syz-ci /syzkaller)
./syz-ci -config /syzkaller/gopath/src/github.com/google/syzkaller/dashboard/config/freebsd/config.ci 2>&1 | tee /syzkaller/syz-ci.log &
EOF

mkisofs -o image.iso -V SYZCI -J -R setup.sh rc.local id_ed25519.pub

expect 2>&1 <<EOF | tee install_log
set timeout 1800
set send_slow {1 0.05}

spawn qemu-system-x86_64 -nographic -smp 2 \
  -drive if=virtio,file=disk.raw,format=raw \
  -net nic,model=virtio -net user -boot once=d -m 4000 -cdrom image.iso

expect timeout { exit 1 } -exact {[Space] to pause}
send -s "\x1b"
expect timeout { exit 1 } "OK "
send -s "set console=comconsole\n"
expect timeout { exit 1 } "OK "
send "boot\n"

expect timeout { exit 1 } "login:"
send -s "root\n"
expect "# "
send -s "mount -t cd9660 /dev/cd0 /mnt\n"
expect "# "
send -s "sh /mnt/setup.sh\n"
expect "# "
send -s "poweroff\n"
expect eof
EOF

i="freebsd-${ARCH}-snapshot-gce.tar.gz"
$TAR -Szcf "$i" disk.raw

cat <<EOF
Done.

To create GCE image run the following commands:

gcloud storage cp --billing-project=syzkaller --predefined-acl=publicRead "$i" gs://syzkaller/
gcloud compute images create ci-freebsd-root --source-uri gs://syzkaller/"$i"

EOF
