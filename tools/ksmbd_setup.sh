#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# ksmbd_setup.sh brings up the in-kernel SMB3 server (ksmbd) inside the target
# VM so that syzkaller's ksmbd descriptions (sys/linux/ksmbd.txt) reach a
# configured, listening server. It configures three transports/paths so the
# fuzzer can exercise the full server:
#   - TCP on 127.0.0.1:445           (always)
#   - SMB Direct / RDMA (SIW or RXE) (if the kernel + rdma-core support it)
#   - Kerberos KDC for the krb5 auth path in session-setup (optional)
#
# Installed into the image by `create-image.sh --add-ksmbd`, and run on every
# boot via a systemd unit. Deliberately idempotent (safe to re-run): it kills
# any running daemon and tolerates already-provisioned state, because the guest
# may reboot many times during a fuzzing campaign. Every optional step is
# non-fatal -- a kernel without RDMA or a host without krb5 still gets a working
# TCP server.
#
# Kernel config expected: CONFIG_SMB_SERVER (ksmbd); plus, for SMB Direct,
# CONFIG_SMB_SERVER_SMBDIRECT and CONFIG_RDMA_RXE / CONFIG_RDMA_SIW / dummy net.

set -u

CONF=/etc/ksmbd/ksmbd.conf
PWDB=/tmp/ksmbd_conf/ksmbdpwd.db
USER=fuzz
PASS=fuzz

log() { echo "[ksmbd_setup] $*"; }

# 1. Share/backing directories (paths referenced by CONF). World-writable
#    because [aclshare] uses `force user = fuzz`: a root-owned 0755 dir would
#    make every fuzzer write fail with EACCES.
log "1/7 creating share/config directories"
mkdir -p /tmp/ksmbd_share /tmp/ksmbd_acl /tmp/ksmbd_priv /tmp/ksmbd_conf
chmod 0777 /tmp/ksmbd_share /tmp/ksmbd_acl /tmp/ksmbd_priv

# 2. Write the server config. Kept in this script so the bring-up is
#    self-contained (no separate config file to install/keep in sync). Maximum
#    attack surface: SMB3.1.1, all features, large buffers, three shares
#    (full-write, ACL-enforced, DesiredAccess-respecting).
log "2/7 writing $CONF"
mkdir -p /etc/ksmbd
cat > "$CONF" <<'EOF'
[global]
	workgroup = WORKGROUP
	netbios name = FUZZHOST
	map to guest = Bad User
	guest account = nobody
	server min protocol = SMB2_10
	server max protocol = SMB3_11
	server string = syzkaller-ksmbd
	smb2 max read = 8388608
	smb2 max write = 8388608
	smb2 max trans = 8388608
	smb2 max credits = 8192
	smbd max io size = 16777216
	smb2 leases = yes
	durable handles = yes
	oplocks = yes
	server multi channel support = yes
	smb3 encryption = enabled
	server signing = auto
	max active sessions = 65536
	max connections = 65536
	max open files = 65536
	deadtime = 0
	ipc timeout = 0
	restrict anonymous = 0

[share]
	path = /tmp/ksmbd_share
	comment = Full feature write share
	read only = no
	guest ok = yes
	force user = root
	force group = root
	create mask = 0777
	directory mask = 0777
	oplocks = yes
	store dos attributes = yes
	follow symlinks = yes
	crossmnt = yes
	inherit owner = yes
	vfs objects = streams_xattr

[aclshare]
	path = /tmp/ksmbd_acl
	comment = ACL enforced share
	read only = no
	guest ok = yes
	force user = fuzz
	valid users = fuzz
	write list = fuzz
	oplocks = yes
	store dos attributes = yes
	follow symlinks = yes
	crossmnt = yes
	inherit owner = yes
	create mask = 0777
	directory mask = 0777
	vfs objects = streams_xattr

[privtest]
	path = /tmp/ksmbd_priv
	comment = Privilege bypass testing (respects DesiredAccess)
	read only = no
	guest ok = no
	valid users = fuzz
	write list = fuzz
	oplocks = yes
	store dos attributes = yes
	vfs objects = streams_xattr
EOF

# 3. Load the module (no-op if ksmbd is built-in).
log "3/7 modprobe ksmbd"
modprobe ksmbd 2>/dev/null || true

# 4. POSIX user `fuzz`. ksmbd.mountd resolves `force user = fuzz` /
#    `valid users = fuzz` via getpwnam() at load; if `fuzz` is missing from
#    /etc/passwd, mountd drops the share and a tree-connect returns
#    BAD_NETWORK_NAME. ksmbd.adduser only populates the SMB user DB, not
#    /etc/passwd, so the POSIX user must exist too.
log "4/7 provisioning POSIX user $USER"
if ! getent passwd "$USER" >/dev/null 2>&1; then
	useradd -m -s /bin/false "$USER" 2>/dev/null || \
		useradd "$USER" 2>/dev/null || \
		log "WARNING: could not create POSIX user $USER; aclshare will be dropped"
fi

# 5. SMB user in the ksmbd password DB.
log "5/7 provisioning ksmbd SMB user $USER"
rm -f "$PWDB"
ksmbd.adduser -C "$CONF" -P "$PWDB" -a "$USER" -p "$PASS" 2>/dev/null || \
	log "WARNING: ksmbd.adduser failed"

# 6. Software RDMA for SMB Direct (non-fatal). Must run BEFORE ksmbd.mountd so
#    the SMB Direct listener can bind to the IB device. Primary path is SIW
#    (iWARP) on a real (non-loopback) interface; RXE (Soft-RoCE) on a dummy
#    interface is the fallback, since RDMA CM needs a routable IP, not lo.
setup_rdma() {
	command -v rdma >/dev/null 2>&1 || { log "     rdma tool absent; SMB Direct skipped"; return; }
	# Modules are usually built-in; modprobe is best-effort for a modular kernel.
	modprobe siw 2>/dev/null || true
	modprobe rdma_rxe 2>/dev/null || true
	modprobe dummy 2>/dev/null || true
	ip link set lo up 2>/dev/null || true

	# Primary: SIW on the first non-loopback interface that is up.
	local iface
	iface=$(ip -o link show up 2>/dev/null | awk -F': ' \
		'$2 != "lo" && $0 !~ /LOOPBACK/ {print $2; exit}')
	if [ -n "${iface:-}" ]; then
		if ! ip -4 addr show "$iface" 2>/dev/null | grep -q 'inet '; then
			ip addr add 192.168.122.50/24 dev "$iface" 2>/dev/null || true
			ip link set "$iface" up 2>/dev/null || true
		fi
		rdma link del siw0 2>/dev/null || true
		if rdma link add siw0 type siw netdev "$iface" 2>/dev/null; then
			log "     SMB Direct: siw0 (SIW/iWARP) on $iface"
			return
		fi
	fi

	# Fallback: RXE (Soft-RoCE) on a dummy interface with a routable IP.
	ip link add dummy0 type dummy 2>/dev/null || true
	ip addr add 10.0.99.1/24 dev dummy0 2>/dev/null || true
	ip link set dummy0 up 2>/dev/null || true
	rdma link del rxe0 2>/dev/null || true
	if rdma link add rxe0 type rxe netdev dummy0 2>/dev/null; then
		log "     SMB Direct: rxe0 (Soft-RoCE) on dummy0 (10.0.99.1)"
	else
		log "     SMB Direct: RDMA link setup failed; TCP only"
	fi
}
log "6/7 setting up Software RDMA (SMB Direct)"
setup_rdma

# 7. Kerberos KDC for the krb5 session-setup path (non-fatal). Gives the
#    kernel's krb5 auth parsing something to talk to; realm FUZZ.LOCAL on
#    127.0.0.1:88.
setup_kdc() {
	command -v krb5kdc >/dev/null 2>&1 || { log "     krb5kdc absent; KDC skipped"; return; }
	mkdir -p /tmp/kdc
	cat > /etc/krb5.conf <<'EOF'
[libdefaults]
  default_realm = FUZZ.LOCAL
  dns_lookup_realm = false
  dns_lookup_kdc = false
[realms]
  FUZZ.LOCAL = {
    kdc = 127.0.0.1
    admin_server = 127.0.0.1
  }
[domain_realm]
  .fuzz.local = FUZZ.LOCAL
EOF
	cat > /tmp/kdc/kdc.conf <<'EOF'
[kdcdefaults]
  kdc_listen = 88
[realms]
  FUZZ.LOCAL = {
    database_name = /tmp/kdc/principal
    key_stash_file = /tmp/kdc/.k5.FUZZ.LOCAL
    max_life = 10h
    max_renewable_life = 7d
  }
EOF
	export KRB5_KDC_PROFILE=/tmp/kdc/kdc.conf
	if [ ! -e /tmp/kdc/principal ]; then
		kdb5_util create -s -r FUZZ.LOCAL -P fuzzpass 2>/dev/null || {
			log "     KDC database creation failed; krb5 path skipped"; return; }
		kadmin.local -q "addprinc -pw fuzz fuzz@FUZZ.LOCAL" 2>/dev/null || true
		kadmin.local -q "addprinc -pw fuzz cifs/127.0.0.1@FUZZ.LOCAL" 2>/dev/null || true
	fi
	pkill -9 krb5kdc 2>/dev/null || true
	krb5kdc -n &
	log "     KDC running (FUZZ.LOCAL, 127.0.0.1:88)"
}
log "7/7 setting up Kerberos KDC (krb5 auth path)"
setup_kdc

# Finally, (re)start the mountd user daemon. Kill any prior instance first so
# this is idempotent across reboots / re-runs.
log "starting ksmbd.mountd"
pkill -9 ksmbd.mountd 2>/dev/null || true
if ! command -v ksmbd.mountd >/dev/null 2>&1; then
	log "ERROR: ksmbd.mountd not found (install ksmbd-tools in the image)"
	exit 1
fi
# No -n: let mountd daemonize (fork to background) so this script returns. With
# -n it stays in the foreground and would block the caller forever.
ksmbd.mountd -C "$CONF" -P "$PWDB"
log "ksmbd.mountd started; server listening on 127.0.0.1:445 (+ SMB Direct if enabled)"
