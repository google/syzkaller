#!/bin/bash

# Copyright 2018 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# ubuntu-setup.sh setups a syzkaller fuzz env automatically.

# 1. C compiler with coverage support
# 2. Linux kernel with coverage additions
# 3. Virtual machine or a physical device
# 4. Syzkaller fuzz

# Author: Nixawk
# Date  : 2018/12/08
# Lab   : Ubuntu 18.04 x86_64 (4.19.6)

# references
# https://github.com/google/syzkaller/blob/master/docs/linux/setup.md
# https://www.kernel.org/doc/html/latest/admin-guide/README.html
# https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
# https://github.com/google/syzkaller/blob/master/tools/create-image.sh
# https://github.com/google/syzkaller/blob/master/tools/demo_setup.sh
# https://github.com/torvalds/linux/blob/master/scripts/kconfig/merge_config.sh
# https://github.com/google/syzkaller/blob/master/dashboard/config/kmsan_from_kasan_config.sh
# https://gist.githubusercontent.com/dvyukov/5f378399ff1a1302d9725f21142ef0d9/raw/9c854e95aaf6e65b7b312d436d310f74af6067ec/gistfile1.txt

export INIT_DIR=`pwd`
export KERNEL_RELEASE_URL="https://www.kernel.org/releases.json"
export KERNEL_RELEASE_VERSION=$(curl -s $KERNEL_RELEASE_URL | grep -A2 "latest_stable" | sed ':a;N;$!ba;s/\n//g' | grep -oP '\d.\d+.\d')
export KERNEL_SOURCE_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-$KERNEL_RELEASE_VERSION.tar.xz"
export KERNEL_PATCH_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/patch-$KERNEL_RELEASE_VERSION.xz"
export GOLANG_URL="https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz"
export KERNEL_SOURCE_FILE=$(basename $KERNEL_SOURCE_URL)
export KERNEL_PATCH_FILE=$(basename $KERNEL_PATCH_URL)
export GOLANG_FILE=$(basename $GOLANG_URL)
export GOROOT="$INIT_DIR/go"
export GOPATH="$INIT_DIR/gopath"
export PATH=$GOROOT/bin:$PATH
export KERNEL_SOURCE_DIR="${KERNEL_SOURCE_FILE%.*.*}"
export KBLD_DIR="$INIT_DIR/build_kernel"
export KCGF_FILE="$KBLD_DIR/.config"
export IMG_RELEASE="stretch"  # /usr/share/debootstrap/scripts/stretch
export IMG_BLD_DIR="$INIT_DIR/build_img"
export IMG_FILE="$INIT_DIR/$IMG_RELEASE.img"

echo "[*] Syzkaller is trying to use [linux-$KERNEL_RELEASE_VERSION]"

function install_dependencies {
    echo "[*] install all dependencies"
    sudo apt-get install -qq -y flex bison libc6-dev libc6-dev-i386 \
	    linux-libc-dev linux-libc-dev:i386 libgmp3-dev \
	    libmpfr-dev libmpc-dev build-essential bc \
            debootstrap qemu-system-x86
}

function check_gcc_coverage {
    echo "[*] check if gcc has coverage feature"
    OPT_COVERAGE=$(MANWIDTH=160 man gcc | grep '      \-fsanitize-coverage')
    if [[ "$OPT_COVERAGE" == *"-fsanitize-coverage"* ]]; then
	echo "[*] gcc is with coverage support"
    else
	echo "[-] gcc is not with coverage support"
	exit 1
    fi
}

function patch_linux_kernel {
    echo "[*] patch linux kernel"
    if [[ ! -f "$INIT_DIR/$KERNEL_SOURCE_FILE" ]]; then
	echo "[*] DOWNLOAD $KERNEL_SOURCE_FILE"
	wget -O "$INIT_DIR/$KERNEL_SOURCE_FILE" -c "$KERNEL_SOURCE_URL"
    else
	echo "[+] $KERNEL_SOURCE_FILE FOUND"
    fi

    if [[ ! -f "$INIT_DIR/$KERNEL_PATCH_FILE" ]]; then
	echo "[*] DOWNLOAD $KERNEL_PATCH_FILE"
	wget -O "$INIT_DIR/$KERNEL_PATCH_FILE" -c "$KERNEL_PATCH_URL"
    else
	echo "[+] $KERNEL_PATCH_FILE FOUND"
    fi

    if [[ ! -d "$KERNEL_SOURCE_DIR" ]]; then
        tar xvf "$KERNEL_SOURCE_FILE" >/dev/null
        cd "$KERNEL_SOURCE_DIR"
        xz -cd ../"$KERNEL_PATCH_FILE" | patch -R -p1
    fi
}

function config_with_sed {
    sed -i "s/^# $1 .*/$1=y/" "$KCGF_FILE"
    sed -i "s/$1=.*/$1=y/" "$KCGF_FILE"
    sed -i "/^#.*$1=.*/s/^#//" "$KCGF_FILE"
}

function build_linux_kernel {
    echo "[*] build linux kernel"
    mkdir -p "$KBLD_DIR"
    cd "$INIT_DIR/$KERNEL_SOURCE_DIR"
    make O="$KBLD_DIR" defconfig
    make O="$KBLD_DIR" kvmconfig

    # To enable coverage collection, which is extremely important for effective
    # fuzzing:
    config_with_sed "CONFIG_KCOV"
    config_with_sed "CONFIG_KCOV_INSTRUMENT_ALL"
    config_with_sed "CONFIG_KCOV_ENABLE_COMPARISONS"
    config_with_sed "CONFIG_DEBUG_KMEMLEAK"
    config_with_sed "CONFIG_DEBUG_INFO"
    config_with_sed "CONFIG_DEBUG_FS"

    config_with_sed "CONFIG_CONFIGFS_FS"
    config_with_sed "CONFIG_SECURITYFS"

    # Enable KASAN for user-after-free and out-of-bounds detection:
    config_with_sed "CONFIG_KASAN"
    config_with_sed "CONFIG_KASAN_INLINE"

    # For detection of enabled syscalls and kernel bitness:
    config_with_sed "CONFIG_KALLSYMS"
    config_with_sed "CONFIG_KALLSYMS_ALL"

    # Sandbox
    config_with_sed "CONFIG_NAMESPACES"
    config_with_sed "CONFIG_UTS_NS"
    config_with_sed "CONFIG_IPC_NS"
    config_with_sed "CONFIG_PID_NS"
    config_with_sed "CONFIG_NET_NS"
    config_with_sed "CONFIG_CGROUP_PIDS"
    config_with_sed "CONFIG_MEMCG"
    config_with_sed "CONFIG_USER_NS"

    # For testing with fault injection enable the following configs
    # (syzkaller will pick it up automatically):
    config_with_sed "CONFIG_FAULT_INJECTION"
    config_with_sed "CONFIG_FAULT_INJECTION_DEBUG_FS"
    config_with_sed "CONFIG_FAILSLAB"
    config_with_sed "CONFIG_FAIL_PAGE_ALLOC"
    config_with_sed "CONFIG_FAIL_MAKE_REQUEST"
    config_with_sed "CONFIG_FAIL_IO_TIMEOUT"
    config_with_sed "CONFIG_FAIL_FUTEX"

    config_with_sed "CONFIG_LOCKDEP"
    config_with_sed "CONFIG_PROVE_LOCKING"
    config_with_sed "CONFIG_DEBUG_ATOMIC_SLEEP"
    config_with_sed "CONFIG_PROVE_RCU"
    config_with_sed "CONFIG_DEBUG_VM"
    config_with_sed "CONFIG_REFCOUNT_FULL"
    config_with_sed "CONFIG_FORTIFY_SOURCE"
    config_with_sed "CONFIG_HARDENED_USERCOPY"
    config_with_sed "CONFIG_LOCKUP_DETECTOR"
    config_with_sed "CONFIG_SOFTLOCKUP_DETECTOR"
    config_with_sed "CONFIG_HARDLOCKUP_DETECTOR"
    config_with_sed "CONFIG_BOOTPARAM_HARDLOCKUP_PANIC"
    config_with_sed "CONFIG_DETECT_HUNG_TASK"
    config_with_sed "CONFIG_WQ_WATCHDOG"

    make O="$KBLD_DIR"
}

function create_image {
    cd "$INIT_DIR"

    set -eux

    # Create a minimal Debian distribution in a directory.
    sudo rm -rf $IMG_BLD_DIR
    mkdir -p $IMG_BLD_DIR
    sudo debootstrap --include=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default $IMG_RELEASE $IMG_BLD_DIR

    # Set some defaults and enable promtless ssh to the machine for root.
    sudo sed -i '/^root/ { s/:x:/::/ }' $IMG_BLD_DIR/etc/passwd
    echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $IMG_BLD_DIR/etc/inittab
    printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $IMG_BLD_DIR/etc/network/interfaces
    echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $IMG_BLD_DIR/etc/fstab
    echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $IMG_BLD_DIR/etc/fstab
    echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $IMG_BLD_DIR/etc/fstab
    echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $IMG_BLD_DIR/etc/fstab
    echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $IMG_BLD_DIR/etc/fstab
    echo "kernel.printk = 7 4 1 3" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo 'debug.exception-trace = 0' | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "net.core.bpf_jit_enable = 1" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "net.core.bpf_jit_kallsyms = 1" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "net.core.bpf_jit_harden = 0" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "kernel.softlockup_all_cpu_backtrace = 1" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "kernel.kptr_restrict = 0" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "kernel.watchdog_thresh = 60" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a $IMG_BLD_DIR/etc/sysctl.conf
    echo -en "127.0.0.1\tlocalhost\n" | sudo tee $IMG_BLD_DIR/etc/hosts
    echo "nameserver 8.8.8.8" | sudo tee -a $IMG_BLD_DIR/etc/resolve.conf
    echo "syzkaller" | sudo tee $IMG_BLD_DIR/etc/hostname
    ssh-keygen -f "$IMG_BLD_DIR/$IMG_RELEASE.id_rsa" -t rsa -N ''
    sudo mkdir -p "$IMG_BLD_DIR/root/.ssh/"
    cat "$IMG_BLD_DIR/$IMG_RELEASE.id_rsa.pub" | sudo tee $IMG_BLD_DIR/root/.ssh/authorized_keys

    sudo chroot $IMG_BLD_DIR /bin/bash -c "apt-get update; apt-get install -y curl tar time strace gcc make sysbench git vim screen usbutils"
    sudo chroot $IMG_BLD_DIR /bin/bash -c "mkdir -p ~; cd ~/; wget https://github.com/kernelslacker/trinity/archive/v1.5.tar.gz -O trinity-1.5.tar.gz; tar -xf trinity-1.5.tar.gz"
    sudo chroot $IMG_BLD_DIR /bin/bash -c "cd ~/trinity-1.5 ; ./configure.sh ; make -j4 ; make install"

    # Build a disk image
    dd if=/dev/zero of="$IMG_FILE" bs=1M seek=2047 count=1
    sudo mkfs.ext4 -F "$IMG_FILE"
    sudo mkdir -p /mnt/$IMG_RELEASE
    sudo mount -o loop "$IMG_FILE" /mnt/$IMG_RELEASE
    sudo cp -a $IMG_BLD_DIR/. /mnt/$IMG_RELEASE/.
    sudo umount /mnt/$IMG_RELEASE
}

function build_img {
    echo "[*] build stretch img"
    if [[ ! -f "$IMG_FILE" ]]; then
	echo "[*] $IMG_FILE is building"
	create_image
    else
	echo "[*] $IMG_FILE FOUND"
    fi
}

function boot_img {
    sudo qemu-system-x86_64 -kernel "$KBLD_DIR/arch/x86/boot/bzImage" \
    -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ" \
    -hda "$IMG_FILE" \
    -net user,hostfwd=tcp::10021-:22 \
    -net nic -enable-kvm -nographic -m 2G -smp 2 \
    -pidfile "$INIT_DIR/vm.pid" 2>&1 | tee "$INIT_DIR/vm.log"
}

function print_ssh_cmd {
    echo "[*] ssh -i \"$IMG_BLD_DIR/$IMG_RELEASE.id_rsa\" -p 10021 -o \"StrictHostKeyChecking no\" root@localhost"
}

function config_syzkaller {
    if [[ ! -f "$INIT_DIR/$GOLANG_FILE" ]]; then
	echo "[*] DOWNLOAD $GOLANG_FILE"
	wget -O "$INIT_DIR/$GOLANG_FILE" -c "$GOLANG_URL"
    else
	echo "[+] $GOLANG_FILE FOUND"
    fi

    echo "$INIT_DIR/$GOLANG_FILE"
    cd "$INIT_DIR" && tar xvf "$INIT_DIR/$GOLANG_FILE" && mkdir "$GOPATH"
    go get -u -d github.com/google/syzkaller/...
    cd "$GOPATH/src/github.com/google/syzkaller/" && make

    cat > "$INIT_DIR/syzkaller.cfg" << EOF
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "$INIT_DIR/syzkaller_workdir",
        "kernel_obj": "$KBLD_DIR",
	"image": "$IMG_FILE",
	"sshkey": "$IMG_BLD_DIR/$IMG_RELEASE.id_rsa",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"procs": 8,
	"type": "qemu",
	"vm": {
		"count": 4,
		"kernel": "$KBLD_DIR/arch/x86/boot/bzImage",
		"cpu": 2,
		"mem": 2048
	}
}
EOF

    sudo "$GOPATH/src/github.com/google/syzkaller/bin/syz-manager" -config "$INIT_DIR/syzkaller.cfg" -debug
}

install_dependencies
check_gcc_coverage
patch_linux_kernel
build_linux_kernel
build_img
print_ssh_cmd
config_syzkaller
