#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Creates an amd64 FreeBSD base VM image (with serial console, root SSH, DHCP)
# and an optional userspace sysroot on a Linux host without root privileges.
#
# Output layout under OUTPUT_DIR (default: ./freebsd-image):
#   userspace/image    - raw FreeBSD disk image suitable for pkg/build UserspaceDir or builder_image
#   userspace/key      - SSH private key for root@vm (omitted when -k is set)
#   userspace/key.pub  - SSH public key (omitted when -k is set)
#   sysroot/           - unpacked FreeBSD headers & libraries for SOURCEDIR_FREEBSD (omitted when -S is set)

set -euo pipefail

ARCH="amd64"
VERSION="16.0-CURRENT"
DISK_SIZE="15G"
OUTPUT_DIR="./freebsd-image"
MIRROR="https://download.freebsd.org"
KEYLESS=0
SKIP_SYSROOT=0

usage() {
	cat <<EOF
Usage: $0 [options]
  -o DIR      Output directory (default: ${OUTPUT_DIR})
  -v VERSION  FreeBSD version, e.g. 16.0-CURRENT or 15.0-RELEASE (default: ${VERSION})
  -s SIZE     Target disk image size (default: ${DISK_SIZE})
  -k          Configure keyless/passwordless root SSH (e.g. for QEMU builder_image).
              WARNING: such an image has an empty root password; only use it as a
              local QEMU kernel_builder_image, never as a network-reachable fuzzing image.
  -S          Skip downloading/extracting the userspace sysroot
  -h          Show this help
EOF
}

while getopts "o:v:s:kSh" opt; do
	case "${opt}" in
		o) OUTPUT_DIR="${OPTARG}" ;;
		v) VERSION="${OPTARG}" ;;
		s) DISK_SIZE="${OPTARG}" ;;
		k) KEYLESS=1 ;;
		S) SKIP_SYSROOT=1 ;;
		h) usage; exit 0 ;;
		*) usage >&2; exit 1 ;;
	esac
done

case "${VERSION}" in
	*-CURRENT|*-STABLE|*-PRERELEASE|*-ALPHA*) TREE="snapshots" ;;
	*) TREE="releases" ;;
esac

QEMU_BIN="qemu-system-x86_64"
REQ_TOOLS=(curl sha512sum sha256sum xz tar expect realpath "${QEMU_BIN}")
(( KEYLESS )) || REQ_TOOLS+=(ssh-keygen)
for tool in "${REQ_TOOLS[@]}"; do
	command -v "${tool}" >/dev/null 2>&1 || { echo "Required tool '${tool}' is missing" >&2; exit 1; }
done

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
USERSPACE_DIR="${OUTPUT_DIR}/userspace"
SYSROOT_DIR="${OUTPUT_DIR}/sysroot"
CACHE_DIR="${OUTPUT_DIR}/.cache"
WORK_DIR="$(mktemp -d "${OUTPUT_DIR}/.work.XXXXXX")"
QEMU_PID_FILE="${WORK_DIR}/qemu.pid"
mkdir -p "${CACHE_DIR}" "${USERSPACE_DIR}"

cleanup() {
	[[ -f "${QEMU_PID_FILE}" ]] && kill "$(tr -d '[:space:]' < "${QEMU_PID_FILE}")" 2>/dev/null || true
	rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

fetch_verified() {
	local url="$1" dst="$2" sum_cmd="$3" expected="$4"
	if [[ -f "${dst}" ]] && echo "${expected}  ${dst}" | "${sum_cmd}" -c - >/dev/null 2>&1; then
		return 0
	fi
	curl --proto '=https' --tlsv1.2 -fL "${url}" -o "${dst}.part"
	mv "${dst}.part" "${dst}"
	echo "${expected}  ${dst}" | "${sum_cmd}" -c -
}

VM_URL_BASE="${MIRROR}/${TREE}/VM-IMAGES/${VERSION}/${ARCH}/Latest"
DIST_URL_BASE="${MIRROR}/${TREE}/${ARCH}/${VERSION}"
RAW_XZ_NAME="FreeBSD-${VERSION}-${ARCH}-ufs.raw.xz"

echo "==> Downloading and verifying FreeBSD ${VERSION} (${ARCH})..."
curl --proto '=https' --tlsv1.2 -fsSL "${VM_URL_BASE}/CHECKSUM.SHA512" -o "${WORK_DIR}/CHECKSUM.SHA512"
EXPECTED_VM_SHA512="$(awk -v ver="${VERSION}" -v arch="${ARCH}" '
	/^SHA512 \(FreeBSD-/ && $0 !~ /BASIC-CLOUDINIT/ && $0 ~ ("FreeBSD-" ver "-" arch "-ufs.*\\.raw\\.xz\\)") {
		print $NF; exit
	}
' "${WORK_DIR}/CHECKSUM.SHA512")"
[[ -n "${EXPECTED_VM_SHA512}" ]] || { echo "Missing SHA512 for ${RAW_XZ_NAME}" >&2; exit 1; }
fetch_verified "${VM_URL_BASE}/${RAW_XZ_NAME}" "${CACHE_DIR}/${RAW_XZ_NAME}" sha512sum "${EXPECTED_VM_SHA512}"

if (( !SKIP_SYSROOT )); then
	curl --proto '=https' --tlsv1.2 -fsSL "${DIST_URL_BASE}/MANIFEST" -o "${WORK_DIR}/MANIFEST"
	fetch_dist() {
		local sum
		sum="$(awk -v f="$1" '$1 == f { print $2; exit }' "${WORK_DIR}/MANIFEST")"
		[[ -n "${sum}" ]] || { echo "Missing SHA256 for $1 in MANIFEST" >&2; exit 1; }
		fetch_verified "${DIST_URL_BASE}/$1" "${CACHE_DIR}/$1" sha256sum "${sum}"
	}
	fetch_dist "base.txz"

	echo "==> Extracting sysroot into ${SYSROOT_DIR}..."
	[[ -d "${SYSROOT_DIR}" ]] && chmod -R u+rwX "${SYSROOT_DIR}" 2>/dev/null || true
	rm -rf "${SYSROOT_DIR}"
	mkdir -p "${SYSROOT_DIR}"
	tar -C "${SYSROOT_DIR}" --no-same-owner --no-same-permissions -xf "${CACHE_DIR}/base.txz" \
		./lib ./usr/lib ./usr/libdata ./usr/include
	if awk '$1 == "lib32.txz" { found=1 } END { exit !found }' "${WORK_DIR}/MANIFEST"; then
		fetch_dist "lib32.txz"
		tar -C "${SYSROOT_DIR}" --no-same-owner --no-same-permissions -xf "${CACHE_DIR}/lib32.txz" ./usr/lib32
	fi
	chmod -R u+rwX "${SYSROOT_DIR}"

	SYSROOT_REAL="$(realpath "${SYSROOT_DIR}")"
	while IFS= read -r -d '' link; do
		target="$(readlink "${link}")"
		if [[ "${target}" == /* ]]; then
			ln -snf "$(realpath -ms --relative-to="$(dirname "${link}")" "${SYSROOT_REAL}/${target#/}")" "${link}"
		fi
	done < <(find "${SYSROOT_REAL}" -type l -print0)
	while IFS= read -r -d '' link; do
		if [[ "$(realpath -m "${link}")" != "${SYSROOT_REAL}/"* ]]; then
			echo "Symlink ${link} escapes sysroot" >&2
			exit 1
		fi
	done < <(find "${SYSROOT_REAL}" -type l -print0)
fi

echo "==> Preparing and customizing VM image (${DISK_SIZE})..."
RAW_TMP="${WORK_DIR}/image.raw"
xz -dc -T0 "${CACHE_DIR}/${RAW_XZ_NAME}" > "${RAW_TMP}"
truncate -s "${DISK_SIZE}" "${RAW_TMP}"

SEED_FILES=(setup.sh)
if (( !KEYLESS )); then
	[[ -f "${USERSPACE_DIR}/key" ]] || ssh-keygen -t ed25519 -N "" -f "${USERSPACE_DIR}/key" -C "syzkaller-freebsd" >/dev/null
	chmod 0600 "${USERSPACE_DIR}/key"
	cp "${USERSPACE_DIR}/key.pub" "${WORK_DIR}/authorized_keys"
	SEED_FILES+=(authorized_keys)
else
	rm -f "${USERSPACE_DIR}/key" "${USERSPACE_DIR}/key.pub"
fi

cat > "${WORK_DIR}/setup.sh" <<'EOF'
#!/bin/sh
set -eux
KEYLESS="$1"
IMG_ID="$2"

if [ "$KEYLESS" = "1" ]; then
	pw mod user root -w none
	cat >> /etc/ssh/sshd_config <<'SSHD_EOF'
PermitRootLogin yes
PermitEmptyPasswords yes
PasswordAuthentication yes
UsePAM no
UseDNS no
SSHD_EOF
else
	install -d -m 0700 /root/.ssh
	install -m 0600 /tmp/seed/authorized_keys /root/.ssh/authorized_keys
	cat >> /etc/ssh/sshd_config <<'SSHD_EOF'
PasswordAuthentication no
PermitRootLogin prohibit-password
UsePAM no
UseDNS no
SSHD_EOF
fi

cat >> /boot/loader.conf <<'LOADER_EOF'
autoboot_delay="-1"
console="comconsole"
LOADER_EOF

cat >> /etc/rc.conf <<'RC_EOF'
hostname="syzkaller"
ifconfig_DEFAULT="DHCP"
sshd_enable="YES"
sendmail_enable="NONE"
sendmail_submit_enable="NO"
sendmail_outbound_enable="NO"
sendmail_msp_queue_enable="NO"
dumpdev="NO"
growfs_enable="YES"
RC_EOF

# Allow growfs to run again if the disk is resized later (e.g. on GCE).
sed -i '' '/KEYWORD: firstboot/d' /etc/rc.d/growfs
/etc/rc.d/growfs onestart || true

# Give GPT partitions unique labels so builder_image and target image never collide in /dev/gpt.
for lbl in rootfs swapfs efiboot0; do
	idx=$(gpart show -l vtbd0 | awk -v l="$lbl" '$4 == l { print $3; exit }')
	[ -n "$idx" ] && gpart modify -i "$idx" -l "${lbl}-${IMG_ID}" vtbd0
	sed -i '' "s|/dev/gpt/${lbl}|/dev/gpt/${lbl}-${IMG_ID}|g" /etc/fstab
done

touch /root/.hushlogin
sync
EOF
chmod 0755 "${WORK_DIR}/setup.sh"

tar -C "${WORK_DIR}" -cf "${WORK_DIR}/seed.tar" "${SEED_FILES[@]}"
truncate -s +1M "${WORK_DIR}/seed.tar"

USE_KVM=0
[[ -r /dev/kvm && -w /dev/kvm ]] && USE_KVM=1
IMG_ID="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

QEMU_BIN="${QEMU_BIN}" USE_KVM="${USE_KVM}" RAW_TMP="${RAW_TMP}" SEED_TAR="${WORK_DIR}/seed.tar" \
	QEMU_PID_FILE="${QEMU_PID_FILE}" KEYLESS="${KEYLESS}" IMG_ID="${IMG_ID}" expect <<'EOF'
set timeout 600
set send_slow {1 0.02}

proc wait_for {pat} {
	expect {
		timeout { puts stderr "Timed out waiting for: $pat"; exit 1 }
		$pat {}
	}
}

set cmd [list $env(QEMU_BIN)]
if {$env(USE_KVM) eq "1"} { lappend cmd -enable-kvm -cpu host,migratable=off }
lappend cmd -nographic -no-reboot -smp 4 -m 4096 -pidfile $env(QEMU_PID_FILE) \
	-drive "if=virtio,file=$env(RAW_TMP),format=raw" \
	-drive "if=virtio,file=$env(SEED_TAR),format=raw,readonly=on" \
	-net nic,model=virtio -net user,restrict=on
spawn {*}$cmd

expect {
	timeout { puts stderr "Timed out waiting for FreeBSD loader"; exit 1 }
	-exact {[Space] to pause} { send -s "\x1b"; exp_continue }
	"OK " {}
}
send -s "set console=comconsole\r"
wait_for "OK "
send -s "boot\r"
wait_for "login:"
send -s "root\r"
wait_for "# "
send -s "mkdir -p /tmp/seed && tar -C /tmp/seed -xf /dev/vtbd1 && sh /tmp/seed/setup.sh $env(KEYLESS) $env(IMG_ID) && echo SYZ_SETUP_''OK\r"
wait_for "SYZ_SETUP_OK"
wait_for "# "
send -s "poweroff\r"
wait_for eof
EOF

mv -f "${RAW_TMP}" "${USERSPACE_DIR}/image"
echo "==> Done: userspace=${USERSPACE_DIR}"
(( SKIP_SYSROOT )) || echo "    sysroot=${SYSROOT_DIR} (export SOURCEDIR_FREEBSD=${SYSROOT_DIR})"
