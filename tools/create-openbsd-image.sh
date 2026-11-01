#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Creates an amd64 OpenBSD artifact bundle on a Linux host without root privileges:
#   userspace/image    - raw OpenBSD target disk image (base sets, serial console, root SSH key, DHCP)
#   userspace/key      - SSH private key for root@vm (reused if already present)
#   userspace/key.pub  - SSH public key
#   builder.raw        - keyless OpenBSD QEMU builder disk image (includes compXX.tgz + UBSan runtime)
#   sysroot/           - unpacked OpenBSD headers & libraries for SOURCEDIR_OPENBSD

set -euo pipefail

ARCH="amd64"
VERSION="snapshots"
TARGET_SIZE="4G"
BUILDER_SIZE="12G"
OUTPUT_DIR="./openbsd-image"
MIRROR="https://cdn.openbsd.org/pub/OpenBSD"
SKIP_USERSPACE=0
SKIP_BUILDER=0
SKIP_SYSROOT=0
JOBS=""

usage() {
	cat <<EOF
Usage: $0 [options]
  -o DIR      Output directory (default: ${OUTPUT_DIR})
  -v VERSION  OpenBSD version, e.g. snapshots or 7.8 (default: ${VERSION})
  -s SIZE     Target userspace/image disk size (default: ${TARGET_SIZE})
  -b SIZE     Keyless builder.raw disk size (default: ${BUILDER_SIZE})
  -U          Skip building target userspace/{image,key,key.pub}
  -B          Skip building keyless builder.raw (it has an empty root password; only use it
              as a local QEMU kernel_builder_image, never as a network-reachable fuzzing image)
  -S          Skip extracting userspace sysroot/
  -j JOBS     Parallel QEMU installs: 1 or 2 (default: auto based on available RAM)
  -h          Show this help

Environment variables:
  OPENBSD_CACHE_DIR  Optional download cache directory
                     (default: \${TMPDIR:-/tmp}/syzkaller-openbsd-cache-\$(id -u))
EOF
}

while getopts "o:v:s:b:UBSj:h" opt; do
	case "${opt}" in
		o) OUTPUT_DIR="${OPTARG}" ;;
		v) VERSION="${OPTARG}" ;;
		s) TARGET_SIZE="${OPTARG}" ;;
		b) BUILDER_SIZE="${OPTARG}" ;;
		U) SKIP_USERSPACE=1 ;;
		B) SKIP_BUILDER=1 ;;
		S) SKIP_SYSROOT=1 ;;
		j) JOBS="${OPTARG}" ;;
		h) usage; exit 0 ;;
		*) usage >&2; exit 1 ;;
	esac
done

if (( SKIP_USERSPACE && SKIP_BUILDER && SKIP_SYSROOT )); then
	echo "Nothing to do (-U, -B, and -S are all set)" >&2
	exit 1
fi

QEMU_BIN="qemu-system-x86_64"
REQ_TOOLS=(curl sha256sum tar)
(( SKIP_SYSROOT )) || REQ_TOOLS+=(realpath)
(( SKIP_USERSPACE && SKIP_BUILDER )) || REQ_TOOLS+=(expect "${QEMU_BIN}")
(( SKIP_USERSPACE )) || REQ_TOOLS+=(ssh-keygen)
for tool in "${REQ_TOOLS[@]}"; do
	command -v "${tool}" >/dev/null 2>&1 || { echo "Required tool '${tool}' is missing" >&2; exit 1; }
done

if [[ -z "${JOBS}" ]]; then
	avail_kb="$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo 2>/dev/null || echo 0)"
	JOBS=$(( avail_kb >= 8388608 ? 2 : 1 ))
fi
[[ "${JOBS}" == "1" || "${JOBS}" == "2" ]] || { echo "Invalid -j '${JOBS}' (expected 1 or 2)" >&2; exit 1; }

mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
USERSPACE_DIR="${OUTPUT_DIR}/userspace"
BUILDER_IMG="${OUTPUT_DIR}/builder.raw"
SYSROOT_DIR="${OUTPUT_DIR}/sysroot"
CACHE_DIR="${OPENBSD_CACHE_DIR:-${TMPDIR:-/tmp}/syzkaller-openbsd-cache-$(id -u)}/${VERSION}-${ARCH}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/syzkaller-openbsd-work.XXXXXX")"
DIST_URL_BASE="${MIRROR}/${VERSION}/${ARCH}"
mkdir -p "${CACHE_DIR}"

cleanup() {
	for pid_file in "${WORK_DIR}"/*/qemu.pid; do
		[[ -f "${pid_file}" ]] && kill "$(tr -d '[:space:]' < "${pid_file}")" 2>/dev/null || true
	done
	rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

echo "==> Downloading and verifying OpenBSD (${VERSION}/${ARCH})..."
curl --proto '=https' --tlsv1.2 -fsSL "${DIST_URL_BASE}/SHA256" -o "${WORK_DIR}/SHA256"
RELNO="$(awk 'match($0, /^SHA256 \(base[0-9]+\.tgz\) = /) { sub(/^SHA256 \(base/, ""); sub(/\.tgz\).*/, ""); print; exit }' "${WORK_DIR}/SHA256")"
[[ -n "${RELNO}" ]] || { echo "Failed to determine release number from ${DIST_URL_BASE}/SHA256" >&2; exit 1; }

fetch_dist() {
	local file="$1" dst="${CACHE_DIR}/$1" expected
	expected="$(awk -v f="(${file})" '$1 == "SHA256" && $2 == f { print $4; exit }' "${WORK_DIR}/SHA256")"
	[[ -n "${expected}" ]] || { echo "Missing SHA256 for ${file}" >&2; exit 1; }
	if [[ -f "${dst}" ]] && echo "${expected}  ${dst}" | sha256sum -c - >/dev/null 2>&1; then
		return 0
	fi
	curl --proto '=https' --tlsv1.2 -fL "${DIST_URL_BASE}/${file}" -o "${dst}.part"
	mv "${dst}.part" "${dst}"
	echo "${expected}  ${dst}" | sha256sum -c -
}

ISO_NAME="install${RELNO}.iso"
(( SKIP_USERSPACE && SKIP_BUILDER )) || fetch_dist "${ISO_NAME}"

if (( !SKIP_SYSROOT )); then
	fetch_dist "base${RELNO}.tgz"
	fetch_dist "comp${RELNO}.tgz"

	echo "==> Extracting sysroot into ${SYSROOT_DIR}..."
	SYSROOT_TMP="${OUTPUT_DIR}/.sysroot.tmp.$$"
	rm -rf "${SYSROOT_TMP}"
	mkdir -p "${SYSROOT_TMP}"
	tar -C "${SYSROOT_TMP}" --no-same-owner --no-same-permissions -xzf "${CACHE_DIR}/base${RELNO}.tgz" \
		./usr/lib ./usr/libdata
	tar -C "${SYSROOT_TMP}" --no-same-owner --no-same-permissions -xzf "${CACHE_DIR}/comp${RELNO}.tgz" \
		./usr/include ./usr/lib ./usr/libdata
	chmod -R u+rwX "${SYSROOT_TMP}"

	SYSROOT_REAL="$(realpath "${SYSROOT_TMP}")"
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

	[[ -d "${SYSROOT_DIR}" ]] && chmod -R u+rwX "${SYSROOT_DIR}" 2>/dev/null || true
	rm -rf "${SYSROOT_DIR}"
	mv "${SYSROOT_TMP}" "${SYSROOT_DIR}"
fi

if (( !SKIP_USERSPACE || !SKIP_BUILDER )); then
	echo "==> Installing OpenBSD VM image(s) in isolated QEMU (jobs=${JOBS})..."
	cat > "${WORK_DIR}/setup.sh" <<'EOF'
#!/bin/sh
set -eux
KEYLESS="$1"
BUILDER="$2"

if [ "$KEYLESS" = "1" ]; then
	usermod -p '' root
	cat >> /etc/ssh/sshd_config <<'SSHD_EOF'
PermitEmptyPasswords yes
PasswordAuthentication yes
SSHD_EOF
else
	usermod -p '*' root
	echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi

cat > /etc/boot.conf <<'BOOT_EOF'
stty com0 115200
set tty com0
set timeout 1
BOOT_EOF

ln -sf /usr/bin/true /usr/libexec/reorder_kernel
pkill -f 'reorder_kernel|/usr/share/relink' || true
while pgrep -f 'reorder_kernel|/usr/share/relink' >/dev/null 2>&1; do
	sleep 1
done
rm -rf /usr/share/relink

perl -i -pne 's/^(ttyC.*)vt220.*/$1unknown off/' /etc/ttys

cat > /etc/rc.conf.local <<'RC_EOF'
cron_flags=NO
library_aslr=NO
ntpd_flags=NO
pf=NO
pflogd_flags=NO
slaacd_flags=NO
smtpd_flags=NO
sndiod_flags=NO
RC_EOF

cat > /etc/sysctl.conf <<'SYSCTL_EOF'
ddb.max_line=0
ddb.max_width=0
hw.smt=1
kern.allowdt=1
SYSCTL_EOF

cat > /etc/rc.local <<'RCLOCAL_EOF'
(
	h=$(printf '%s\r\n' \
		'GET /computeMetadata/v1/instance/hostname HTTP/1.0' \
		'Host: metadata.google.internal' \
		'Metadata-Flavor: Google' \
		'' | nc -w 1 169.254.169.254 80 2>/dev/null | tail -n 1)
	if [ -n "$h" ]; then
		printf '%s\n' "$h" > /etc/myname
		hostname "$h"
	fi
) >/dev/null 2>&1 &
RCLOCAL_EOF

(cd /dev && for i in 0 1 2 3 4 5 6 7; do sh MAKEDEV "tap$i"; done)

if [ "$BUILDER" = "1" ]; then
	for clang_lib in /usr/lib/clang/*/lib; do
		if [ -f "$clang_lib/libclang_rt.ubsan_minimal.a" ]; then
			mkdir -p "$clang_lib/openbsd"
			ln -sf "$clang_lib/libclang_rt.ubsan_minimal.a" \
				"$clang_lib/openbsd/libclang_rt.ubsan_standalone-x86_64.a"
			ar crs "$clang_lib/openbsd/libclang_rt.ubsan_standalone_cxx-x86_64.a"
		fi
	done
fi

touch /root/.hushlogin
sync
EOF
	chmod 0755 "${WORK_DIR}/setup.sh"

	USE_KVM=0
	[[ -r /dev/kvm && -w /dev/kvm ]] && USE_KVM=1

	build_vm_image() {
		local label="$1" final_dst="$2" disk_size="$3" keyless="$4" builder="$5" root_ssh_pubkey="$6"
		local vm_work="${WORK_DIR}/${label}" raw_tmp="${final_dst}.tmp.$$"
		local allow_root_ssh="prohibit-password" sets_line="-* +bsd +bsd.mp +base*" install_pass
		(( keyless )) && allow_root_ssh="yes"
		(( builder )) && sets_line+=" +comp*"
		install_pass="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"

		mkdir -p "${vm_work}"
		rm -f "${raw_tmp}"
		truncate -s "${disk_size}" "${raw_tmp}"

		cat > "${vm_work}/auto_install.conf" <<EOF
System hostname = syzkaller
DNS domain name = syzkaller
DNS nameservers = none
Which network interface = vio0
IPv4 address for vio0 = autoconf
IPv6 address for vio0 = none
Default IPv4 route = none
Password for root account = ${install_pass}
Public ssh key for root account = ${root_ssh_pubkey}
Do you expect to run the X Window System = no
Change the default console to com0 = yes
Which speed should com0 use = 115200
Setup a user = no
Allow root ssh login = ${allow_root_ssh}
What timezone = UTC
Encrypt the root disk = no
Which disk = sd0
Use (W)hole disk or (E)dit the MBR = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = auto
URL to autopartitioning template for disklabel = file:/disklabel.template
Location of sets = cd0
Set name(s) = ${sets_line} done
Directory does not contain SHA256.sig. Continue without verification = yes
EOF
		cat > "${vm_work}/disklabel.template" <<'EOF'
/	1G-*	95%
swap	256M-1G	5%
EOF
		cp "${WORK_DIR}/setup.sh" "${vm_work}/setup.sh"
		tar -C "${vm_work}" -cf "${vm_work}/seed.tar" auto_install.conf disklabel.template setup.sh
		truncate -s +1M "${vm_work}/seed.tar"

		echo "    [${label}] Installing (${disk_size})..."
		if ! QEMU_BIN="${QEMU_BIN}" USE_KVM="${USE_KVM}" RAW_TMP="${raw_tmp}" \
			ISO_PATH="${CACHE_DIR}/${ISO_NAME}" SEED_TAR="${vm_work}/seed.tar" \
			INSTALL_PASS="${install_pass}" KEYLESS="${keyless}" BUILDER="${builder}" \
			QEMU_PID_FILE="${vm_work}/qemu.pid" expect <<'EOF' > "${vm_work}/install.log" 2>&1
set timeout 1200
set send_slow {1 0.02}

proc wait_for {pat msg} {
	expect {
		timeout { puts stderr $msg; exit 1 }
		$pat {}
	}
}

set raw_escaped [string map {, ,,} $env(RAW_TMP)]
set seed_escaped [string map {, ,,} $env(SEED_TAR)]
set cmd [list $env(QEMU_BIN)]
if {$env(USE_KVM) eq "1"} { lappend cmd -enable-kvm -cpu host,migratable=off }
lappend cmd -nographic -smp 4 -m 3072 -pidfile $env(QEMU_PID_FILE) \
	-drive "if=virtio,file=$raw_escaped,format=raw" \
	-drive "if=virtio,file=$seed_escaped,format=raw,readonly=on" \
	-cdrom $env(ISO_PATH) -boot once=d \
	-net nic,model=virtio -net user,restrict=on
spawn {*}$cmd

wait_for "boot>" "Timed out waiting for OpenBSD CD boot prompt"
send -s "set tty com0\r"
wait_for "boot>" "Timed out switching console to com0"
send -s "\r"

wait_for "(I)nstall, (U)pgrade, (A)utoinstall or (S)hell?" "Timed out waiting for installer prompt"
send -s "s\r"
wait_for "# " "Timed out waiting for installer shell"
send -s "(cd /dev && sh MAKEDEV sd1) && mkdir -p /tmp/seed && tar -C /tmp/seed -xf /dev/rsd1c && cp /tmp/seed/auto_install.conf /tmp/seed/disklabel.template / && chmod 0644 /auto_install.conf /disklabel.template && /autoinstall\r"

expect {
	timeout { puts stderr "Timed out during OpenBSD autoinstall"; exit 1 }
	"Question has no answer in response file:" { puts stderr "OpenBSD autoinstall missing response"; exit 1 }
	"failed; check /tmp/ai/ai.log" { puts stderr "OpenBSD autoinstall failed"; exit 1 }
	"CONGRATULATIONS!" {}
}

expect {
	timeout { puts stderr "Timed out waiting for first-boot login prompt"; exit 1 }
	"boot>" { send -s "\r"; exp_continue }
	"Enter pathname of shell or RETURN for sh:" {
		send -s "\r"
		wait_for "# " "Timed out in single-user shell"
		send -s "exit\r"
		exp_continue
	}
	"login:" {}
}
send -s "root\r"
wait_for "Password:" "Timed out waiting for root password prompt"
send -s "$env(INSTALL_PASS)\r"
wait_for "# " "Timed out waiting for installed root shell"

send -s "mkdir -p /tmp/seed && tar -C /tmp/seed -xf /dev/rsd1c && sh /tmp/seed/setup.sh $env(KEYLESS) $env(BUILDER) && echo SYZ_SETUP_''OK || echo SYZ_SETUP_''FAIL\r"
expect {
	timeout { puts stderr "Timed out running setup.sh"; exit 1 }
	"SYZ_SETUP_FAIL" { puts stderr "setup.sh failed inside OpenBSD VM"; exit 1 }
	"SYZ_SETUP_OK" {}
}
wait_for "# " "Timed out waiting for prompt after setup.sh"
send -s "halt -p\r"
wait_for eof "Timed out waiting for OpenBSD VM shutdown"
EOF
		then
			rm -f "${raw_tmp}"
			echo "ERROR: [${label}] QEMU install failed; last 80 log lines:" >&2
			tail -n 80 "${vm_work}/install.log" >&2 || true
			return 1
		fi
		mv -f "${raw_tmp}" "${final_dst}"
		echo "    [${label}] Done -> ${final_dst}"
	}

	pids=()
	if (( !SKIP_USERSPACE )); then
		mkdir -p "${USERSPACE_DIR}"
		if [[ ! -f "${USERSPACE_DIR}/key" ]]; then
			rm -f "${USERSPACE_DIR}/key.pub"
			ssh-keygen -t ed25519 -N "" -f "${USERSPACE_DIR}/key" -C "syzkaller-openbsd" >/dev/null
		fi
		chmod 0600 "${USERSPACE_DIR}/key"
		[[ -f "${USERSPACE_DIR}/key.pub" ]] || ssh-keygen -y -f "${USERSPACE_DIR}/key" > "${USERSPACE_DIR}/key.pub"
		build_vm_image "userspace" "${USERSPACE_DIR}/image" "${TARGET_SIZE}" 0 0 "$(<"${USERSPACE_DIR}/key.pub")" &
		pids+=($!)
		if (( JOBS == 1 )); then
			wait "${pids[0]}"
			pids=()
		fi
	fi
	rc=0
	if (( !SKIP_BUILDER )); then
		build_vm_image "builder" "${BUILDER_IMG}" "${BUILDER_SIZE}" 1 1 "none" || rc=1
	fi
	for pid in "${pids[@]}"; do
		wait "${pid}" || rc=1
	done
	(( rc == 0 )) || exit 1
fi

echo "==> Done:"
(( SKIP_USERSPACE )) || echo "    userspace=${USERSPACE_DIR}"
(( SKIP_BUILDER )) || echo "    builder=${BUILDER_IMG}"
(( SKIP_SYSROOT )) || echo "    sysroot=${SYSROOT_DIR} (export SOURCEDIR_OPENBSD=${SYSROOT_DIR})"
