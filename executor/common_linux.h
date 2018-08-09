// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if SYZ_EXECUTOR
struct cover_t;
static void cover_reset(cover_t* cov);
#endif

#if SYZ_EXECUTOR || SYZ_THREADED
#include <linux/futex.h>
#include <pthread.h>

typedef struct {
	int state;
} event_t;

static void event_init(event_t* ev)
{
	ev->state = 0;
}

static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	if (ev->state)
		fail("event already set");
	__atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &ev->state, FUTEX_WAKE);
}

static void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, &ev->state, FUTEX_WAIT, 0, 0);
}

static int event_isset(event_t* ev)
{
	return __atomic_load_n(&ev->state, __ATOMIC_ACQUIRE);
}

static int event_timedwait(event_t* ev, uint64 timeout)
{
	uint64 start = current_time_ms();
	uint64 now = start;
	for (;;) {
		uint64 remain = timeout - (now - start);
		struct timespec ts;
		ts.tv_sec = remain / 1000;
		ts.tv_nsec = (remain % 1000) * 1000 * 1000;
		syscall(SYS_futex, &ev->state, FUTEX_WAIT, 0, &ts);
		if (__atomic_load_n(&ev->state, __ATOMIC_RELAXED))
			return 1;
		now = current_time_ms();
		if (now - start > timeout)
			return 0;
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_TUN_ENABLE || SYZ_ENABLE_NETDEV
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

static void vsnprintf_check(char* str, size_t size, const char* format, va_list args)
{
	int rv;

	rv = vsnprintf(str, size, format, args);
	if (rv < 0)
		fail("tun: snprintf failed");
	if ((size_t)rv >= size)
		fail("tun: string '%s...' doesn't fit into buffer", str);
}

#define COMMAND_MAX_LEN 128
#define PATH_PREFIX "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "
#define PATH_PREFIX_LEN (sizeof(PATH_PREFIX) - 1)

static void execute_command(bool panic, const char* format, ...)
{
	va_list args;
	char command[PATH_PREFIX_LEN + COMMAND_MAX_LEN];
	int rv;

	va_start(args, format);
	// Executor process does not have any env, including PATH.
	// On some distributions, system/shell adds a minimal PATH, on some it does not.
	// Set own standard PATH to make it work across distributions.
	memcpy(command, PATH_PREFIX, PATH_PREFIX_LEN);
	vsnprintf_check(command + PATH_PREFIX_LEN, COMMAND_MAX_LEN, format, args);
	va_end(args);
	rv = system(command);
	if (rv) {
		if (panic)
			fail("command '%s' failed: %d", &command[0], rv);
		debug("command '%s': %d\n", &command[0], rv);
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_TUN_ENABLE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

static int tunfd = -1;
static int tun_frags_enabled;

// We just need this to be large enough to hold headers that we parse (ethernet/ip/tcp).
// Rest of the packet (if any) will be silently truncated which is fine.
#define SYZ_TUN_MAX_PACKET_SIZE 1000

#define TUN_IFACE "syz_tun"

#define LOCAL_MAC "aa:aa:aa:aa:aa:aa"
#define REMOTE_MAC "aa:aa:aa:aa:aa:bb"

#define LOCAL_IPV4 "172.20.20.170"
#define REMOTE_IPV4 "172.20.20.187"

#define LOCAL_IPV6 "fe80::aa"
#define REMOTE_IPV6 "fe80::bb"

#ifndef IFF_NAPI
#define IFF_NAPI 0x0010
#endif
#ifndef IFF_NAPI_FRAGS
#define IFF_NAPI_FRAGS 0x0020
#endif

static void initialize_tun(void)
{
#if SYZ_EXECUTOR
	if (!flag_enable_tun)
		return;
#endif
	tunfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (tunfd == -1) {
#if SYZ_EXECUTOR
		fail("tun: can't open /dev/net/tun\n");
#else
		printf("tun: can't open /dev/net/tun: please enable CONFIG_TUN=y\n");
		printf("otherwise fuzzing or reproducing might not work as intended\n");
		return;
#endif
	}
	// Remap tun onto higher fd number to hide it from fuzzer and to keep
	// fd numbers stable regardless of whether tun is opened or not (also see kMaxFd).
	const int kTunFd = 240;
	if (dup2(tunfd, kTunFd) < 0)
		fail("dup2(tunfd, kTunFd) failed");
	close(tunfd);
	tunfd = kTunFd;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, TUN_IFACE, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS;
	if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0) {
		// IFF_NAPI_FRAGS requires root, so try without it.
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0)
			fail("tun: ioctl(TUNSETIFF) failed");
	}
	// If IFF_NAPI_FRAGS is not supported it will be silently dropped,
	// so query the effective flags.
	if (ioctl(tunfd, TUNGETIFF, (void*)&ifr) < 0)
		fail("tun: ioctl(TUNGETIFF) failed");
	tun_frags_enabled = (ifr.ifr_flags & IFF_NAPI_FRAGS) != 0;
	debug("tun_frags_enabled=%d\n", tun_frags_enabled);

	// Disable IPv6 DAD, otherwise the address remains unusable until DAD completes.
	// Don't panic because this is an optional config.
	execute_command(0, "sysctl -w net.ipv6.conf.%s.accept_dad=0", TUN_IFACE);

	// Disable IPv6 router solicitation to prevent IPv6 spam.
	// Don't panic because this is an optional config.
	execute_command(0, "sysctl -w net.ipv6.conf.%s.router_solicitations=0", TUN_IFACE);
	// There seems to be no way to disable IPv6 MTD to prevent more IPv6 spam.

	execute_command(1, "ip link set dev %s address %s", TUN_IFACE, LOCAL_MAC);
	execute_command(1, "ip addr add %s/24 dev %s", LOCAL_IPV4, TUN_IFACE);
	execute_command(1, "ip neigh add %s lladdr %s dev %s nud permanent",
			REMOTE_IPV4, REMOTE_MAC, TUN_IFACE);
	// Don't panic because ipv6 may be not enabled in kernel.
	execute_command(0, "ip -6 addr add %s/120 dev %s", LOCAL_IPV6, TUN_IFACE);
	execute_command(0, "ip -6 neigh add %s lladdr %s dev %s nud permanent",
			REMOTE_IPV6, REMOTE_MAC, TUN_IFACE);
	execute_command(1, "ip link set dev %s up", TUN_IFACE);
}
#endif

#if SYZ_EXECUTOR || SYZ_ENABLE_NETDEV
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>

// Addresses are chosen to be in the same subnet as tun addresses.
#define DEV_IPV4 "172.20.20.%d"
#define DEV_IPV6 "fe80::%02hx"
#define DEV_MAC "aa:aa:aa:aa:aa:%02hx"

static void snprintf_check(char* str, size_t size, const char* format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintf_check(str, size, format, args);
	va_end(args);
}

// We test in a separate namespace, which does not have any network devices initially (even lo).
// Create/up as many as we can.
static void initialize_netdevices(void)
{
#if SYZ_EXECUTOR
	if (!flag_enable_net_dev)
		return;
#endif
	unsigned i;
	const char* devtypes[] = {"ip6gretap", "bridge", "vcan", "bond", "team"};
	// If you extend this array, also update netdev_addr_id in vnet.txt.
	const char* devnames[] = {"lo", "sit0", "bridge0", "vcan0", "tunl0",
				  "gre0", "gretap0", "ip_vti0", "ip6_vti0",
				  "ip6tnl0", "ip6gre0", "ip6gretap0",
				  "erspan0", "bond0", "veth0", "veth1", "team0",
				  "veth0_to_bridge", "veth1_to_bridge",
				  "veth0_to_bond", "veth1_to_bond",
				  "veth0_to_team", "veth1_to_team"};
	const char* devmasters[] = {"bridge", "bond", "team"};

	for (i = 0; i < sizeof(devtypes) / (sizeof(devtypes[0])); i++)
		execute_command(0, "ip link add dev %s0 type %s", devtypes[i], devtypes[i]);
	// This adds connected veth0 and veth1 devices.
	execute_command(0, "ip link add type veth");

	// This creates connected bridge/bond/team_slave devices of type veth,
	// and makes them slaves of bridge/bond/team devices, respectively.
	// Note: slave devices don't need MAC/IP addresses, only master devices.
	//       veth0_to_* is not slave devices, which still need ip addresses.
	for (i = 0; i < sizeof(devmasters) / (sizeof(devmasters[0])); i++) {
		execute_command(0, "ip link add name %s_slave_0 type veth peer name veth0_to_%s", devmasters[i], devmasters[i]);
		execute_command(0, "ip link add name %s_slave_1 type veth peer name veth1_to_%s", devmasters[i], devmasters[i]);
		execute_command(0, "ip link set %s_slave_0 master %s0", devmasters[i], devmasters[i]);
		execute_command(0, "ip link set %s_slave_1 master %s0", devmasters[i], devmasters[i]);
		execute_command(0, "ip link set veth0_to_%s up", devmasters[i]);
		execute_command(0, "ip link set veth1_to_%s up", devmasters[i]);
	}
	// bond/team_slave_* will set up automatically when set their master.
	// But bridge_slave_* need to set up manually.
	execute_command(0, "ip link set bridge_slave_0 up");
	execute_command(0, "ip link set bridge_slave_1 up");

	for (i = 0; i < sizeof(devnames) / (sizeof(devnames[0])); i++) {
		char addr[32];
		// Assign some unique address to devices. Some devices won't up without this.
		// Devices that don't need these addresses will simply ignore them.
		// Shift addresses by 10 because 0 subnet address can mean special things.
		snprintf_check(addr, sizeof(addr), DEV_IPV4, i + 10);
		execute_command(0, "ip -4 addr add %s/24 dev %s", addr, devnames[i]);
		snprintf_check(addr, sizeof(addr), DEV_IPV6, i + 10);
		execute_command(0, "ip -6 addr add %s/120 dev %s", addr, devnames[i]);
		snprintf_check(addr, sizeof(addr), DEV_MAC, i + 10);
		execute_command(0, "ip link set dev %s address %s", devnames[i], addr);
		execute_command(0, "ip link set dev %s up", devnames[i]);
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_TUN_ENABLE && (__NR_syz_extract_tcp_res || SYZ_REPEAT)
#include <errno.h>

static int read_tun(char* data, int size)
{
	if (tunfd < 0)
		return -1;

	int rv = read(tunfd, data, size);
	if (rv < 0) {
		if (errno == EAGAIN)
			return -1;
		// Tun sometimes returns this, unclear if it's a kernel bug or not.
		if (errno == EBADFD)
			return -1;
		fail("tun: read failed with %d", rv);
	}
	return rv;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet && SYZ_TUN_ENABLE
#include <stdbool.h>
#include <sys/uio.h>

#define MAX_FRAGS 4
struct vnet_fragmentation {
	uint32 full;
	uint32 count;
	uint32 frags[MAX_FRAGS];
};

static long syz_emit_ethernet(long a0, long a1, long a2)
{
	// syz_emit_ethernet(len len[packet], packet ptr[in, eth_packet], frags ptr[in, vnet_fragmentation, opt])
	// vnet_fragmentation {
	// 	full	int32[0:1]
	// 	count	int32[1:4]
	// 	frags	array[int32[0:4096], 4]
	// }
	if (tunfd < 0)
		return (uintptr_t)-1;

	uint32 length = a0;
	char* data = (char*)a1;
	debug_dump_data(data, length);

	struct vnet_fragmentation* frags = (struct vnet_fragmentation*)a2;
	struct iovec vecs[MAX_FRAGS + 1];
	uint32 nfrags = 0;
	if (!tun_frags_enabled || frags == NULL) {
		vecs[nfrags].iov_base = data;
		vecs[nfrags].iov_len = length;
		nfrags++;
	} else {
		bool full = true;
		uint32 i, count = 0;
		NONFAILING(full = frags->full);
		NONFAILING(count = frags->count);
		if (count > MAX_FRAGS)
			count = MAX_FRAGS;
		for (i = 0; i < count && length != 0; i++) {
			uint32 size = 0;
			NONFAILING(size = frags->frags[i]);
			if (size > length)
				size = length;
			vecs[nfrags].iov_base = data;
			vecs[nfrags].iov_len = size;
			nfrags++;
			data += size;
			length -= size;
		}
		if (length != 0 && (full || nfrags == 0)) {
			vecs[nfrags].iov_base = data;
			vecs[nfrags].iov_len = length;
			nfrags++;
		}
	}
	return writev(tunfd, vecs, nfrags);
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT && SYZ_TUN_ENABLE
static void flush_tun()
{
#if SYZ_EXECUTOR
	if (!flag_enable_tun)
		return;
#endif
	char data[SYZ_TUN_MAX_PACKET_SIZE];
	while (read_tun(&data[0], sizeof(data)) != -1) {
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_extract_tcp_res && SYZ_TUN_ENABLE
#ifndef __ANDROID__
// Can't include <linux/ipv6.h>, since it causes
// conflicts due to some structs redefinition.
struct ipv6hdr {
	__u8 priority : 4,
	    version : 4;
	__u8 flow_lbl[3];

	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;

	struct in6_addr saddr;
	struct in6_addr daddr;
};
#endif

struct tcp_resources {
	uint32 seq;
	uint32 ack;
};

static long syz_extract_tcp_res(long a0, long a1, long a2)
{
	// syz_extract_tcp_res(res ptr[out, tcp_resources], seq_inc int32, ack_inc int32)

	if (tunfd < 0)
		return (uintptr_t)-1;

	char data[SYZ_TUN_MAX_PACKET_SIZE];
	int rv = read_tun(&data[0], sizeof(data));
	if (rv == -1)
		return (uintptr_t)-1;
	size_t length = rv;
	debug_dump_data(data, length);

	struct tcphdr* tcphdr;

	if (length < sizeof(struct ethhdr))
		return (uintptr_t)-1;
	struct ethhdr* ethhdr = (struct ethhdr*)&data[0];

	if (ethhdr->h_proto == htons(ETH_P_IP)) {
		if (length < sizeof(struct ethhdr) + sizeof(struct iphdr))
			return (uintptr_t)-1;
		struct iphdr* iphdr = (struct iphdr*)&data[sizeof(struct ethhdr)];
		if (iphdr->protocol != IPPROTO_TCP)
			return (uintptr_t)-1;
		if (length < sizeof(struct ethhdr) + iphdr->ihl * 4 + sizeof(struct tcphdr))
			return (uintptr_t)-1;
		tcphdr = (struct tcphdr*)&data[sizeof(struct ethhdr) + iphdr->ihl * 4];
	} else {
		if (length < sizeof(struct ethhdr) + sizeof(struct ipv6hdr))
			return (uintptr_t)-1;
		struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)&data[sizeof(struct ethhdr)];
		// TODO: parse and skip extension headers.
		if (ipv6hdr->nexthdr != IPPROTO_TCP)
			return (uintptr_t)-1;
		if (length < sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr))
			return (uintptr_t)-1;
		tcphdr = (struct tcphdr*)&data[sizeof(struct ethhdr) + sizeof(struct ipv6hdr)];
	}

	struct tcp_resources* res = (struct tcp_resources*)a0;
	NONFAILING(res->seq = htonl((ntohl(tcphdr->seq) + (uint32)a1)));
	NONFAILING(res->ack = htonl((ntohl(tcphdr->ack_seq) + (uint32)a2)));

	debug("extracted seq: %08x\n", res->seq);
	debug("extracted ack: %08x\n", res->ack);

	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_open_dev
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static long syz_open_dev(long a0, long a1, long a2)
{
	if (a0 == 0xc || a0 == 0xb) {
		// syz_open_dev$char(dev const[0xc], major intptr, minor intptr) fd
		// syz_open_dev$block(dev const[0xb], major intptr, minor intptr) fd
		char buf[128];
		sprintf(buf, "/dev/%s/%d:%d", a0 == 0xc ? "char" : "block", (uint8)a1, (uint8)a2);
		return open(buf, O_RDWR, 0);
	} else {
		// syz_open_dev(dev strconst, id intptr, flags flags[open_flags]) fd
		char buf[1024];
		char* hash;
		NONFAILING(strncpy(buf, (char*)a0, sizeof(buf) - 1));
		buf[sizeof(buf) - 1] = 0;
		while ((hash = strchr(buf, '#'))) {
			*hash = '0' + (char)(a1 % 10); // 10 devices should be enough for everyone.
			a1 /= 10;
		}
		return open(buf, a2, 0);
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_open_procfs
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static long syz_open_procfs(long a0, long a1)
{
	// syz_open_procfs(pid pid, file ptr[in, string[procfs_file]]) fd

	char buf[128];
	memset(buf, 0, sizeof(buf));
	if (a0 == 0) {
		NONFAILING(snprintf(buf, sizeof(buf), "/proc/self/%s", (char*)a1));
	} else if (a0 == -1) {
		NONFAILING(snprintf(buf, sizeof(buf), "/proc/thread-self/%s", (char*)a1));
	} else {
		NONFAILING(snprintf(buf, sizeof(buf), "/proc/self/task/%d/%s", (int)a0, (char*)a1));
	}
	int fd = open(buf, O_RDWR);
	if (fd == -1)
		fd = open(buf, O_RDONLY);
	return fd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_open_pts
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

static long syz_open_pts(long a0, long a1)
{
	// syz_openpts(fd fd[tty], flags flags[open_flags]) fd[tty]
	int ptyno = 0;
	if (ioctl(a0, TIOCGPTN, &ptyno))
		return -1;
	char buf[128];
	sprintf(buf, "/dev/pts/%d", ptyno);
	return open(buf, a1, 0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_init_net_socket
#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const int kInitNetNsFd = 239; // see kMaxFd
// syz_init_net_socket opens a socket in init net namespace.
// Used for families that can only be created in init net namespace.
static long syz_init_net_socket(long domain, long type, long proto)
{
	int netns = open("/proc/self/ns/net", O_RDONLY);
	if (netns == -1)
		return netns;
	if (setns(kInitNetNsFd, 0))
		return -1;
	int sock = syscall(__NR_socket, domain, type, proto);
	int err = errno;
	if (setns(netns, 0))
		fail("setns(netns) failed");
	close(netns);
	errno = err;
	return sock;
}
#else
static long syz_init_net_socket(long domain, long type, long proto)
{
	return syscall(__NR_socket, domain, type, proto);
}
#endif
#endif

#if SYZ_EXECUTOR || __NR_syz_genetlink_get_family_id
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>

static long syz_genetlink_get_family_id(long name)
{
	char buf[512] = {0};
	struct nlmsghdr* hdr = (struct nlmsghdr*)buf;
	struct genlmsghdr* genlhdr = (struct genlmsghdr*)NLMSG_DATA(hdr);
	struct nlattr* attr = (struct nlattr*)(genlhdr + 1);
	hdr->nlmsg_len = sizeof(*hdr) + sizeof(*genlhdr) + sizeof(*attr) + GENL_NAMSIZ;
	hdr->nlmsg_type = GENL_ID_CTRL;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	genlhdr->cmd = CTRL_CMD_GETFAMILY;
	attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	attr->nla_len = sizeof(*attr) + GENL_NAMSIZ;
	NONFAILING(strncpy((char*)(attr + 1), (char*)name, GENL_NAMSIZ));
	struct iovec iov = {hdr, hdr->nlmsg_len};
	struct sockaddr_nl addr = {0};
	addr.nl_family = AF_NETLINK;
	debug("syz_genetlink_get_family_id(%s)\n", (char*)(attr + 1));
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd == -1) {
		debug("syz_genetlink_get_family_id: socket failed: %d\n", errno);
		return -1;
	}
	struct msghdr msg = {&addr, sizeof(addr), &iov, 1, NULL, 0, 0};
	if (sendmsg(fd, &msg, 0) == -1) {
		debug("syz_genetlink_get_family_id: sendmsg failed: %d\n", errno);
		close(fd);
		return -1;
	}
	ssize_t n = recv(fd, buf, sizeof(buf), 0);
	close(fd);
	if (n <= 0) {
		debug("syz_genetlink_get_family_id: recv failed: %d\n", errno);
		return -1;
	}
	if (hdr->nlmsg_type != GENL_ID_CTRL) {
		debug("syz_genetlink_get_family_id: wrong reply type: %d\n", hdr->nlmsg_type);
		return -1;
	}
	for (; (char*)attr < buf + n; attr = (struct nlattr*)((char*)attr + NLMSG_ALIGN(attr->nla_len))) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID)
			return *(uint16*)(attr + 1);
	}
	debug("syz_genetlink_get_family_id: no CTRL_ATTR_FAMILY_ID attr\n");
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mount_image || __NR_syz_read_part_table
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct fs_image_segment {
	void* data;
	uintptr_t size;
	uintptr_t offset;
};

#define IMAGE_MAX_SEGMENTS 4096
#define IMAGE_MAX_SIZE (129 << 20)

#if GOARCH_386
#define SYZ_memfd_create 356
#elif GOARCH_amd64
#define SYZ_memfd_create 319
#elif GOARCH_arm
#define SYZ_memfd_create 385
#elif GOARCH_arm64
#define SYZ_memfd_create 279
#elif GOARCH_ppc64le
#define SYZ_memfd_create 360
#endif
#endif

#if SYZ_EXECUTOR || __NR_syz_read_part_table
// syz_read_part_table(size intptr, nsegs len[segments], segments ptr[in, array[fs_image_segment]])
static long syz_read_part_table(unsigned long size, unsigned long nsegs, long segments)
{
	char loopname[64], linkname[64];
	int loopfd, err = 0, res = -1;
	unsigned long i, j;
	// See the comment in syz_mount_image.
	struct fs_image_segment* segs = (struct fs_image_segment*)segments;

	if (nsegs > IMAGE_MAX_SEGMENTS)
		nsegs = IMAGE_MAX_SEGMENTS;
	for (i = 0; i < nsegs; i++) {
		if (segs[i].size > IMAGE_MAX_SIZE)
			segs[i].size = IMAGE_MAX_SIZE;
		segs[i].offset %= IMAGE_MAX_SIZE;
		if (segs[i].offset > IMAGE_MAX_SIZE - segs[i].size)
			segs[i].offset = IMAGE_MAX_SIZE - segs[i].size;
		if (size < segs[i].offset + segs[i].offset)
			size = segs[i].offset + segs[i].offset;
	}
	if (size > IMAGE_MAX_SIZE)
		size = IMAGE_MAX_SIZE;
	int memfd = syscall(SYZ_memfd_create, "syz_read_part_table", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (ftruncate(memfd, size)) {
		err = errno;
		goto error_close_memfd;
	}
	for (i = 0; i < nsegs; i++) {
		if (pwrite(memfd, segs[i].data, segs[i].size, segs[i].offset) < 0) {
			debug("syz_read_part_table: pwrite[%u] failed: %d\n", (int)i, errno);
		}
	}
	snprintf(loopname, sizeof(loopname), "/dev/loop%llu", procid);
	loopfd = open(loopname, O_RDWR);
	if (loopfd == -1) {
		err = errno;
		goto error_close_memfd;
	}
	if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
		if (errno != EBUSY) {
			err = errno;
			goto error_close_loop;
		}
		ioctl(loopfd, LOOP_CLR_FD, 0);
		usleep(1000);
		if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
			err = errno;
			goto error_close_loop;
		}
	}
	struct loop_info64 info;
	if (ioctl(loopfd, LOOP_GET_STATUS64, &info)) {
		err = errno;
		goto error_clear_loop;
	}
#if SYZ_EXECUTOR
	cover_reset(0);
#endif
	info.lo_flags |= LO_FLAGS_PARTSCAN;
	if (ioctl(loopfd, LOOP_SET_STATUS64, &info)) {
		err = errno;
		goto error_clear_loop;
	}
	res = 0;
	// If we managed to parse some partitions, symlink them into our work dir.
	for (i = 1, j = 0; i < 8; i++) {
		snprintf(loopname, sizeof(loopname), "/dev/loop%llup%d", procid, (int)i);
		struct stat statbuf;
		if (stat(loopname, &statbuf) == 0) {
			snprintf(linkname, sizeof(linkname), "./file%d", (int)j++);
			if (symlink(loopname, linkname)) {
				debug("syz_read_part_table: symlink(%s, %s) failed: %d\n", loopname, linkname, errno);
			}
		}
	}
error_clear_loop:
	ioctl(loopfd, LOOP_CLR_FD, 0);
error_close_loop:
	close(loopfd);
error_close_memfd:
	close(memfd);
error:
	errno = err;
	return res;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mount_image
#include <string.h>
#include <sys/mount.h>

//syz_mount_image(fs ptr[in, string[disk_filesystems]], dir ptr[in, filename], size intptr, nsegs len[segments], segments ptr[in, array[fs_image_segment]], flags flags[mount_flags], opts ptr[in, fs_options[vfat_options]])
//fs_image_segment {
//	data	ptr[in, array[int8]]
//	size	len[data, intptr]
//	offset	intptr
//}
static long syz_mount_image(long fsarg, long dir, unsigned long size, unsigned long nsegs, long segments, long flags, long optsarg)
{
	char loopname[64], fs[32], opts[256];
	int loopfd, err = 0, res = -1;
	unsigned long i;
	// Strictly saying we ought to do a nonfailing copyout of segments into a local var.
	// But some filesystems have large number of segments (2000+),
	// we can't allocate that much on stack and allocating elsewhere is problematic,
	// so we just use the memory allocated by fuzzer.
	struct fs_image_segment* segs = (struct fs_image_segment*)segments;

	if (nsegs > IMAGE_MAX_SEGMENTS)
		nsegs = IMAGE_MAX_SEGMENTS;
	for (i = 0; i < nsegs; i++) {
		if (segs[i].size > IMAGE_MAX_SIZE)
			segs[i].size = IMAGE_MAX_SIZE;
		segs[i].offset %= IMAGE_MAX_SIZE;
		if (segs[i].offset > IMAGE_MAX_SIZE - segs[i].size)
			segs[i].offset = IMAGE_MAX_SIZE - segs[i].size;
		if (size < segs[i].offset + segs[i].offset)
			size = segs[i].offset + segs[i].offset;
	}
	if (size > IMAGE_MAX_SIZE)
		size = IMAGE_MAX_SIZE;
	int memfd = syscall(SYZ_memfd_create, "syz_mount_image", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (ftruncate(memfd, size)) {
		err = errno;
		goto error_close_memfd;
	}
	for (i = 0; i < nsegs; i++) {
		if (pwrite(memfd, segs[i].data, segs[i].size, segs[i].offset) < 0) {
			debug("syz_mount_image: pwrite[%u] failed: %d\n", (int)i, errno);
		}
	}
	snprintf(loopname, sizeof(loopname), "/dev/loop%llu", procid);
	loopfd = open(loopname, O_RDWR);
	if (loopfd == -1) {
		err = errno;
		goto error_close_memfd;
	}
	if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
		if (errno != EBUSY) {
			err = errno;
			goto error_close_loop;
		}
		ioctl(loopfd, LOOP_CLR_FD, 0);
		usleep(1000);
		if (ioctl(loopfd, LOOP_SET_FD, memfd)) {
			err = errno;
			goto error_close_loop;
		}
	}
	mkdir((char*)dir, 0777);
	memset(fs, 0, sizeof(fs));
	NONFAILING(strncpy(fs, (char*)fsarg, sizeof(fs) - 1));
	memset(opts, 0, sizeof(opts));
	// Leave some space for the additional options we append below.
	NONFAILING(strncpy(opts, (char*)optsarg, sizeof(opts) - 32));
	if (strcmp(fs, "iso9660") == 0) {
		flags |= MS_RDONLY;
	} else if (strncmp(fs, "ext", 3) == 0) {
		// For ext2/3/4 we have to have errors=continue because the image
		// can contain errors=panic flag and can legally crash kernel.
		if (strstr(opts, "errors=panic") || strstr(opts, "errors=remount-ro") == 0)
			strcat(opts, ",errors=continue");
	} else if (strcmp(fs, "xfs") == 0) {
		// For xfs we need nouuid because xfs has a global uuids table
		// and if two parallel executors mounts fs with the same uuid, second mount fails.
		strcat(opts, ",nouuid");
	}
	debug("syz_mount_image: size=%llu segs=%llu loop='%s' dir='%s' fs='%s' flags=%llu opts='%s'\n", (uint64)size, (uint64)nsegs, loopname, (char*)dir, fs, (uint64)flags, opts);
#if SYZ_EXECUTOR
	cover_reset(0);
#endif
	if (mount(loopname, (char*)dir, fs, flags, opts)) {
		err = errno;
		goto error_clear_loop;
	}
	res = 0;
error_clear_loop:
	ioctl(loopfd, LOOP_CLR_FD, 0);
error_close_loop:
	close(loopfd);
error_close_memfd:
	close(memfd);
error:
	errno = err;
	return res;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#if defined(__x86_64__)
#include "common_kvm_amd64.h"
#elif defined(__aarch64__)
#include "common_kvm_arm64.h"
#else
static long syz_kvm_setup_cpu(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7)
{
	return 0;
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_FAULT_INJECTION || SYZ_SANDBOX_NAMESPACE || SYZ_ENABLE_CGROUPS
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		int err = errno;
		close(fd);
		errno = err;
		return false;
	}
	close(fd);
	return true;
}
#endif

#if SYZ_EXECUTOR || SYZ_RESET_NET_NAMESPACE
#include <errno.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

// checkpoint/reset_net_namespace partially resets net namespace to initial state
// after each test. Currently it resets only ipv4 netfilter state.
// Ideally, we just create a new net namespace for each test,
// however it's too slow (1-1.5 seconds per namespace, not parallelizable).

// Linux headers do not compile for C++, so we have to define the structs manualy.
#define XT_TABLE_SIZE 1536
#define XT_MAX_ENTRIES 10

struct xt_counters {
	uint64 pcnt, bcnt;
};

struct ipt_getinfo {
	char name[32];
	unsigned int valid_hooks;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int num_entries;
	unsigned int size;
};

struct ipt_get_entries {
	char name[32];
	unsigned int size;
	void* entrytable[XT_TABLE_SIZE / sizeof(void*)];
};

struct ipt_replace {
	char name[32];
	unsigned int valid_hooks;
	unsigned int num_entries;
	unsigned int size;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int num_counters;
	struct xt_counters* counters;
	char entrytable[XT_TABLE_SIZE];
};

struct ipt_table_desc {
	const char* name;
	struct ipt_getinfo info;
	struct ipt_replace replace;
};

static struct ipt_table_desc ipv4_tables[] = {
    {.name = "filter"},
    {.name = "nat"},
    {.name = "mangle"},
    {.name = "raw"},
    {.name = "security"},
};

static struct ipt_table_desc ipv6_tables[] = {
    {.name = "filter"},
    {.name = "nat"},
    {.name = "mangle"},
    {.name = "raw"},
    {.name = "security"},
};

#define IPT_BASE_CTL 64
#define IPT_SO_SET_REPLACE (IPT_BASE_CTL)
#define IPT_SO_GET_INFO (IPT_BASE_CTL)
#define IPT_SO_GET_ENTRIES (IPT_BASE_CTL + 1)

struct arpt_getinfo {
	char name[32];
	unsigned int valid_hooks;
	unsigned int hook_entry[3];
	unsigned int underflow[3];
	unsigned int num_entries;
	unsigned int size;
};

struct arpt_get_entries {
	char name[32];
	unsigned int size;
	void* entrytable[XT_TABLE_SIZE / sizeof(void*)];
};

struct arpt_replace {
	char name[32];
	unsigned int valid_hooks;
	unsigned int num_entries;
	unsigned int size;
	unsigned int hook_entry[3];
	unsigned int underflow[3];
	unsigned int num_counters;
	struct xt_counters* counters;
	char entrytable[XT_TABLE_SIZE];
};

struct arpt_table_desc {
	const char* name;
	struct arpt_getinfo info;
	struct arpt_replace replace;
};

static struct arpt_table_desc arpt_tables[] = {
    {.name = "filter"},
};

#define ARPT_BASE_CTL 96
#define ARPT_SO_SET_REPLACE (ARPT_BASE_CTL)
#define ARPT_SO_GET_INFO (ARPT_BASE_CTL)
#define ARPT_SO_GET_ENTRIES (ARPT_BASE_CTL + 1)

static void checkpoint_iptables(struct ipt_table_desc* tables, int num_tables, int family, int level)
{
	struct ipt_get_entries entries;
	socklen_t optlen;
	int fd, i;

	fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("iptable checkpoint %d: socket failed", family);
	}
	for (i = 0; i < num_tables; i++) {
		struct ipt_table_desc* table = &tables[i];
		strcpy(table->info.name, table->name);
		strcpy(table->replace.name, table->name);
		optlen = sizeof(table->info);
		if (getsockopt(fd, level, IPT_SO_GET_INFO, &table->info, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			fail("iptable checkpoint %s/%d: getsockopt(IPT_SO_GET_INFO)", table->name, family);
		}
		debug("iptable checkpoint %s/%d: checkpoint entries=%d hooks=%x size=%d\n",
		      table->name, family, table->info.num_entries,
		      table->info.valid_hooks, table->info.size);
		if (table->info.size > sizeof(table->replace.entrytable))
			fail("iptable checkpoint %s/%d: table size is too large: %u",
			     table->name, family, table->info.size);
		if (table->info.num_entries > XT_MAX_ENTRIES)
			fail("iptable checkpoint %s/%d: too many counters: %u",
			     table->name, family, table->info.num_entries);
		memset(&entries, 0, sizeof(entries));
		strcpy(entries.name, table->name);
		entries.size = table->info.size;
		optlen = sizeof(entries) - sizeof(entries.entrytable) + table->info.size;
		if (getsockopt(fd, level, IPT_SO_GET_ENTRIES, &entries, &optlen))
			fail("iptable checkpoint %s/%d: getsockopt(IPT_SO_GET_ENTRIES)",
			     table->name, family);
		table->replace.valid_hooks = table->info.valid_hooks;
		table->replace.num_entries = table->info.num_entries;
		table->replace.size = table->info.size;
		memcpy(table->replace.hook_entry, table->info.hook_entry, sizeof(table->replace.hook_entry));
		memcpy(table->replace.underflow, table->info.underflow, sizeof(table->replace.underflow));
		memcpy(table->replace.entrytable, entries.entrytable, table->info.size);
	}
	close(fd);
}

static void reset_iptables(struct ipt_table_desc* tables, int num_tables, int family, int level)
{
	struct xt_counters counters[XT_MAX_ENTRIES];
	struct ipt_get_entries entries;
	struct ipt_getinfo info;
	socklen_t optlen;
	int fd, i;

	fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("iptable %d: socket failed", family);
	}
	for (i = 0; i < num_tables; i++) {
		struct ipt_table_desc* table = &tables[i];
		if (table->info.valid_hooks == 0)
			continue;
		memset(&info, 0, sizeof(info));
		strcpy(info.name, table->name);
		optlen = sizeof(info);
		if (getsockopt(fd, level, IPT_SO_GET_INFO, &info, &optlen))
			fail("iptable %s/%d: getsockopt(IPT_SO_GET_INFO)", table->name, family);
		if (memcmp(&table->info, &info, sizeof(table->info)) == 0) {
			memset(&entries, 0, sizeof(entries));
			strcpy(entries.name, table->name);
			entries.size = table->info.size;
			optlen = sizeof(entries) - sizeof(entries.entrytable) + entries.size;
			if (getsockopt(fd, level, IPT_SO_GET_ENTRIES, &entries, &optlen))
				fail("iptable %s/%d: getsockopt(IPT_SO_GET_ENTRIES)", table->name, family);
			if (memcmp(table->replace.entrytable, entries.entrytable, table->info.size) == 0)
				continue;
		}
		debug("iptable %s/%d: resetting\n", table->name, family);
		table->replace.num_counters = info.num_entries;
		table->replace.counters = counters;
		optlen = sizeof(table->replace) - sizeof(table->replace.entrytable) + table->replace.size;
		if (setsockopt(fd, level, IPT_SO_SET_REPLACE, &table->replace, optlen))
			fail("iptable %s/%d: setsockopt(IPT_SO_SET_REPLACE)", table->name, family);
	}
	close(fd);
}

static void checkpoint_arptables(void)
{
	struct arpt_get_entries entries;
	socklen_t optlen;
	unsigned i;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("arptable checkpoint: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (i = 0; i < sizeof(arpt_tables) / sizeof(arpt_tables[0]); i++) {
		struct arpt_table_desc* table = &arpt_tables[i];
		strcpy(table->info.name, table->name);
		strcpy(table->replace.name, table->name);
		optlen = sizeof(table->info);
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO, &table->info, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			fail("arptable checkpoint %s: getsockopt(ARPT_SO_GET_INFO)", table->name);
		}
		debug("arptable checkpoint %s: entries=%d hooks=%x size=%d\n",
		      table->name, table->info.num_entries, table->info.valid_hooks, table->info.size);
		if (table->info.size > sizeof(table->replace.entrytable))
			fail("arptable checkpoint %s: table size is too large: %u",
			     table->name, table->info.size);
		if (table->info.num_entries > XT_MAX_ENTRIES)
			fail("arptable checkpoint %s: too many counters: %u",
			     table->name, table->info.num_entries);
		memset(&entries, 0, sizeof(entries));
		strcpy(entries.name, table->name);
		entries.size = table->info.size;
		optlen = sizeof(entries) - sizeof(entries.entrytable) + table->info.size;
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES, &entries, &optlen))
			fail("arptable checkpoint %s: getsockopt(ARPT_SO_GET_ENTRIES)", table->name);
		table->replace.valid_hooks = table->info.valid_hooks;
		table->replace.num_entries = table->info.num_entries;
		table->replace.size = table->info.size;
		memcpy(table->replace.hook_entry, table->info.hook_entry, sizeof(table->replace.hook_entry));
		memcpy(table->replace.underflow, table->info.underflow, sizeof(table->replace.underflow));
		memcpy(table->replace.entrytable, entries.entrytable, table->info.size);
	}
	close(fd);
}

static void reset_arptables()
{
	struct xt_counters counters[XT_MAX_ENTRIES];
	struct arpt_get_entries entries;
	struct arpt_getinfo info;
	socklen_t optlen;
	unsigned i;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("arptable: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (i = 0; i < sizeof(arpt_tables) / sizeof(arpt_tables[0]); i++) {
		struct arpt_table_desc* table = &arpt_tables[i];
		if (table->info.valid_hooks == 0)
			continue;
		memset(&info, 0, sizeof(info));
		strcpy(info.name, table->name);
		optlen = sizeof(info);
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO, &info, &optlen))
			fail("arptable %s:getsockopt(ARPT_SO_GET_INFO)", table->name);
		if (memcmp(&table->info, &info, sizeof(table->info)) == 0) {
			memset(&entries, 0, sizeof(entries));
			strcpy(entries.name, table->name);
			entries.size = table->info.size;
			optlen = sizeof(entries) - sizeof(entries.entrytable) + entries.size;
			if (getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES, &entries, &optlen))
				fail("arptable %s: getsockopt(ARPT_SO_GET_ENTRIES)", table->name);
			if (memcmp(table->replace.entrytable, entries.entrytable, table->info.size) == 0)
				continue;
			debug("arptable %s: data changed\n", table->name);
		} else {
			debug("arptable %s: header changed\n", table->name);
		}
		debug("arptable %s: resetting\n", table->name);
		table->replace.num_counters = info.num_entries;
		table->replace.counters = counters;
		optlen = sizeof(table->replace) - sizeof(table->replace.entrytable) + table->replace.size;
		if (setsockopt(fd, SOL_IP, ARPT_SO_SET_REPLACE, &table->replace, optlen))
			fail("arptable %s: setsockopt(ARPT_SO_SET_REPLACE)", table->name);
	}
	close(fd);
}

#include <linux/if.h>
#include <linux/netfilter_bridge/ebtables.h>

struct ebt_table_desc {
	const char* name;
	struct ebt_replace replace;
	char entrytable[XT_TABLE_SIZE];
};

static struct ebt_table_desc ebt_tables[] = {
    {.name = "filter"},
    {.name = "nat"},
    {.name = "broute"},
};

static void checkpoint_ebtables(void)
{
	socklen_t optlen;
	unsigned i;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("ebtable checkpoint: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (i = 0; i < sizeof(ebt_tables) / sizeof(ebt_tables[0]); i++) {
		struct ebt_table_desc* table = &ebt_tables[i];
		strcpy(table->replace.name, table->name);
		optlen = sizeof(table->replace);
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_INFO, &table->replace, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			fail("ebtable checkpoint %s: getsockopt(EBT_SO_GET_INIT_INFO)", table->name);
		}
		debug("ebtable checkpoint %s: entries=%d hooks=%x size=%d\n",
		      table->name, table->replace.nentries, table->replace.valid_hooks,
		      table->replace.entries_size);
		if (table->replace.entries_size > sizeof(table->entrytable))
			fail("ebtable checkpoint %s: table size is too large: %u",
			     table->name, table->replace.entries_size);
		table->replace.num_counters = 0;
		table->replace.entries = table->entrytable;
		optlen = sizeof(table->replace) + table->replace.entries_size;
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_ENTRIES, &table->replace, &optlen))
			fail("ebtable checkpoint %s: getsockopt(EBT_SO_GET_INIT_ENTRIES)", table->name);
	}
	close(fd);
}

static void reset_ebtables()
{
	struct ebt_replace replace;
	char entrytable[XT_TABLE_SIZE];
	socklen_t optlen;
	unsigned i, j, h;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("ebtable: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (i = 0; i < sizeof(ebt_tables) / sizeof(ebt_tables[0]); i++) {
		struct ebt_table_desc* table = &ebt_tables[i];
		if (table->replace.valid_hooks == 0)
			continue;
		memset(&replace, 0, sizeof(replace));
		strcpy(replace.name, table->name);
		optlen = sizeof(replace);
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INFO, &replace, &optlen))
			fail("ebtable %s: getsockopt(EBT_SO_GET_INFO)", table->name);
		replace.num_counters = 0;
		table->replace.entries = 0;
		for (h = 0; h < NF_BR_NUMHOOKS; h++)
			table->replace.hook_entry[h] = 0;
		if (memcmp(&table->replace, &replace, sizeof(table->replace)) == 0) {
			memset(&entrytable, 0, sizeof(entrytable));
			replace.entries = entrytable;
			optlen = sizeof(replace) + replace.entries_size;
			if (getsockopt(fd, SOL_IP, EBT_SO_GET_ENTRIES, &replace, &optlen))
				fail("ebtable %s: getsockopt(EBT_SO_GET_ENTRIES)", table->name);
			if (memcmp(table->entrytable, entrytable, replace.entries_size) == 0)
				continue;
		}
		debug("ebtable %s: resetting\n", table->name);
		// Kernel does not seem to return actual entry points (wat?).
		for (j = 0, h = 0; h < NF_BR_NUMHOOKS; h++) {
			if (table->replace.valid_hooks & (1 << h)) {
				table->replace.hook_entry[h] = (struct ebt_entries*)table->entrytable + j;
				j++;
			}
		}
		table->replace.entries = table->entrytable;
		optlen = sizeof(table->replace) + table->replace.entries_size;
		if (setsockopt(fd, SOL_IP, EBT_SO_SET_ENTRIES, &table->replace, optlen))
			fail("ebtable %s: setsockopt(EBT_SO_SET_ENTRIES)", table->name);
	}
	close(fd);
}

static void checkpoint_net_namespace(void)
{
#if SYZ_EXECUTOR
	if (flag_sandbox == sandbox_setuid)
		return;
#endif
	checkpoint_ebtables();
	checkpoint_arptables();
	checkpoint_iptables(ipv4_tables, sizeof(ipv4_tables) / sizeof(ipv4_tables[0]), AF_INET, SOL_IP);
	checkpoint_iptables(ipv6_tables, sizeof(ipv6_tables) / sizeof(ipv6_tables[0]), AF_INET6, SOL_IPV6);
}

static void reset_net_namespace(void)
{
#if SYZ_EXECUTOR
	if (flag_sandbox == sandbox_setuid)
		return;
#endif
	reset_ebtables();
	reset_arptables();
	reset_iptables(ipv4_tables, sizeof(ipv4_tables) / sizeof(ipv4_tables[0]), AF_INET, SOL_IP);
	reset_iptables(ipv6_tables, sizeof(ipv6_tables) / sizeof(ipv6_tables[0]), AF_INET6, SOL_IPV6);
}
#endif

#if SYZ_EXECUTOR || SYZ_ENABLE_CGROUPS
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

static void setup_cgroups()
{
	if (mkdir("/syzcgroup", 0777)) {
		debug("mkdir(/syzcgroup) failed: %d\n", errno);
	}
	if (mkdir("/syzcgroup/unified", 0777)) {
		debug("mkdir(/syzcgroup/unified) failed: %d\n", errno);
	}
	if (mount("none", "/syzcgroup/unified", "cgroup2", 0, NULL)) {
		debug("mount(cgroup2) failed: %d\n", errno);
	}
	if (chmod("/syzcgroup/unified", 0777)) {
		debug("chmod(/syzcgroup/unified) failed: %d\n", errno);
	}
	if (!write_file("/syzcgroup/unified/cgroup.subtree_control", "+cpu +memory +io +pids +rdma")) {
		debug("write(cgroup.subtree_control) failed: %d\n", errno);
	}
	if (mkdir("/syzcgroup/cpu", 0777)) {
		debug("mkdir(/syzcgroup/cpu) failed: %d\n", errno);
	}
	if (mount("none", "/syzcgroup/cpu", "cgroup", 0, "cpuset,cpuacct,perf_event,hugetlb")) {
		debug("mount(cgroup cpu) failed: %d\n", errno);
	}
	if (!write_file("/syzcgroup/cpu/cgroup.clone_children", "1")) {
		debug("write(/syzcgroup/cpu/cgroup.clone_children) failed: %d\n", errno);
	}
	if (chmod("/syzcgroup/cpu", 0777)) {
		debug("chmod(/syzcgroup/cpu) failed: %d\n", errno);
	}
	if (mkdir("/syzcgroup/net", 0777)) {
		debug("mkdir(/syzcgroup/net) failed: %d\n", errno);
	}
	if (mount("none", "/syzcgroup/net", "cgroup", 0, "net_cls,net_prio,devices,freezer")) {
		debug("mount(cgroup net) failed: %d\n", errno);
	}
	if (chmod("/syzcgroup/net", 0777)) {
		debug("chmod(/syzcgroup/net) failed: %d\n", errno);
	}
}

// TODO(dvyukov): this should be under a separate define for separate minimization,
// but for now we bundle this with cgroups.
static void setup_binfmt_misc()
{
	if (mount(0, "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, 0)) {
		debug("mount(binfmt_misc) failed: %d\n", errno);
	}
	if (!write_file("/proc/sys/fs/binfmt_misc/register", ":syz0:M:0:\x01::./file0:")) {
		debug("write(/proc/sys/fs/binfmt_misc/register, syz0) failed: %d\n", errno);
	}
	if (!write_file("/proc/sys/fs/binfmt_misc/register", ":syz1:M:1:\x02::./file0:POC")) {
		debug("write(/proc/sys/fs/binfmt_misc/register, syz1) failed: %d\n", errno);
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
#include <errno.h>
#include <sys/mount.h>

static void setup_common()
{
	if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
		debug("mount(fusectl) failed: %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_ENABLE_CGROUPS
	setup_cgroups();
	setup_binfmt_misc();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
#include <sched.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>

static void loop();

static void sandbox_common()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
	setsid();

#if SYZ_EXECUTOR || __NR_syz_init_net_socket
	int netns = open("/proc/self/ns/net", O_RDONLY);
	if (netns == -1)
		fail("open(/proc/self/ns/net) failed");
	if (dup2(netns, kInitNetNsFd) < 0)
		fail("dup2(netns, kInitNetNsFd) failed");
	close(netns);
#endif

	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = 160 << 20;
	setrlimit(RLIMIT_AS, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 8 << 20;
	setrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 136 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 256; // see kMaxFd
	setrlimit(RLIMIT_NOFILE, &rlim);

	// CLONE_NEWNS/NEWCGROUP cause EINVAL on some systems,
	// so we do them separately of clone in do_sandbox_namespace.
	if (unshare(CLONE_NEWNS)) {
		debug("unshare(CLONE_NEWNS): %d\n", errno);
	}
	if (unshare(CLONE_NEWIPC)) {
		debug("unshare(CLONE_NEWIPC): %d\n", errno);
	}
	if (unshare(0x02000000)) {
		debug("unshare(CLONE_NEWCGROUP): %d\n", errno);
	}
	if (unshare(CLONE_NEWUTS)) {
		debug("unshare(CLONE_NEWUTS): %d\n", errno);
	}
	if (unshare(CLONE_SYSVSEM)) {
		debug("unshare(CLONE_SYSVSEM): %d\n", errno);
	}
}

int wait_for_loop(int pid)
{
	if (pid < 0)
		fail("sandbox fork failed");
	debug("spawned loop pid %d\n", pid);
	int status = 0;
	while (waitpid(-1, &status, __WALL) != pid) {
	}
	return WEXITSTATUS(status);
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
#include <sched.h>
#include <sys/types.h>

static int do_sandbox_none(void)
{
	// CLONE_NEWPID takes effect for the first child of the current process,
	// so we do it before fork to make the loop "init" process of the namespace.
	// We ought to do fail here, but sandbox=none is used in pkg/ipc tests
	// and they are usually run under non-root.
	// Also since debug is stripped by pkg/csource, we need to do {}
	// even though we generally don't do {} around single statements.
	if (unshare(CLONE_NEWPID)) {
		debug("unshare(CLONE_NEWPID): %d\n", errno);
	}
	int pid = fork();
	if (pid != 0)
		return wait_for_loop(pid);

	setup_common();
	sandbox_common();
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_TUN_ENABLE
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_ENABLE_NETDEV
	initialize_netdevices();
#endif
	loop();
	doexit(1);
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_SETUID
#include <grp.h>
#include <sched.h>
#include <sys/prctl.h>

static int do_sandbox_setuid(void)
{
	if (unshare(CLONE_NEWPID)) {
		debug("unshare(CLONE_NEWPID): %d\n", errno);
	}
	int pid = fork();
	if (pid != 0)
		return wait_for_loop(pid);

	setup_common();
	sandbox_common();
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_TUN_ENABLE
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_ENABLE_NETDEV
	initialize_netdevices();
#endif

	const int nobody = 65534;
	if (setgroups(0, NULL))
		fail("failed to setgroups");
	if (syscall(SYS_setresgid, nobody, nobody, nobody))
		fail("failed to setresgid");
	if (syscall(SYS_setresuid, nobody, nobody, nobody))
		fail("failed to setresuid");

	// This is required to open /proc/self/* files.
	// Otherwise they are owned by root and we can't open them after setuid.
	// See task_dump_owner function in kernel.
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);

	loop();
	doexit(1);
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NAMESPACE
#include <linux/capability.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>

static int real_uid;
static int real_gid;
__attribute__((aligned(64 << 10))) static char sandbox_stack[1 << 20];

static int namespace_sandbox_proc(void* arg)
{
	sandbox_common();

	// /proc/self/setgroups is not present on some systems, ignore error.
	write_file("/proc/self/setgroups", "deny");
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid))
		fail("write of /proc/self/uid_map failed");
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid))
		fail("write of /proc/self/gid_map failed");

	// CLONE_NEWNET must always happen before tun setup,
	// because we want the tun device in the test namespace.
	if (unshare(CLONE_NEWNET))
		fail("unshare(CLONE_NEWNET)");
#if SYZ_EXECUTOR || SYZ_TUN_ENABLE
	// We setup tun here as it needs to be in the test net namespace,
	// which in turn needs to be in the test user namespace.
	// However, IFF_NAPI_FRAGS will fail as we are not root already.
	// There does not seem to be a call sequence that would satisfy all of that.
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_ENABLE_NETDEV
	initialize_netdevices();
#endif

	if (mkdir("./syz-tmp", 0777))
		fail("mkdir(syz-tmp) failed");
	if (mount("", "./syz-tmp", "tmpfs", 0, NULL))
		fail("mount(tmpfs) failed");
	if (mkdir("./syz-tmp/newroot", 0777))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/dev", 0700))
		fail("mkdir failed");
	unsigned bind_mount_flags = MS_BIND | MS_REC | MS_PRIVATE;
	if (mount("/dev", "./syz-tmp/newroot/dev", NULL, bind_mount_flags, NULL))
		fail("mount(dev) failed");
	if (mkdir("./syz-tmp/newroot/proc", 0700))
		fail("mkdir failed");
	if (mount(NULL, "./syz-tmp/newroot/proc", "proc", 0, NULL))
		fail("mount(proc) failed");
	if (mkdir("./syz-tmp/newroot/selinux", 0700))
		fail("mkdir failed");
	// selinux mount used to be at /selinux, but then moved to /sys/fs/selinux.
	const char* selinux_path = "./syz-tmp/newroot/selinux";
	if (mount("/selinux", selinux_path, NULL, bind_mount_flags, NULL)) {
		if (errno != ENOENT)
			fail("mount(/selinux) failed");
		if (mount("/sys/fs/selinux", selinux_path, NULL, bind_mount_flags, NULL) && errno != ENOENT)
			fail("mount(/sys/fs/selinux) failed");
	}
	if (mkdir("./syz-tmp/newroot/sys", 0700))
		fail("mkdir failed");
	if (mount("/sys", "./syz-tmp/newroot/sys", 0, bind_mount_flags, NULL))
		fail("mount(sysfs) failed");
#if SYZ_EXECUTOR || SYZ_ENABLE_CGROUPS
	if (mkdir("./syz-tmp/newroot/syzcgroup", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/unified", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/cpu", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/net", 0700))
		fail("mkdir failed");
	if (mount("/syzcgroup/unified", "./syz-tmp/newroot/syzcgroup/unified", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup2, MS_BIND) failed: %d\n", errno);
	}
	if (mount("/syzcgroup/cpu", "./syz-tmp/newroot/syzcgroup/cpu", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup/cpu, MS_BIND) failed: %d\n", errno);
	}
	if (mount("/syzcgroup/net", "./syz-tmp/newroot/syzcgroup/net", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup/net, MS_BIND) failed: %d\n", errno);
	}
#endif
	if (mkdir("./syz-tmp/pivot", 0777))
		fail("mkdir failed");
	if (syscall(SYS_pivot_root, "./syz-tmp", "./syz-tmp/pivot")) {
		debug("pivot_root failed\n");
		if (chdir("./syz-tmp"))
			fail("chdir failed");
	} else {
		debug("pivot_root OK\n");
		if (chdir("/"))
			fail("chdir failed");
		if (umount2("./pivot", MNT_DETACH))
			fail("umount failed");
	}
	if (chroot("./newroot"))
		fail("chroot failed");
	if (chdir("/"))
		fail("chdir failed");

	// Drop CAP_SYS_PTRACE so that test processes can't attach to parent processes.
	// Previously it lead to hangs because the loop process stopped due to SIGSTOP.
	// Note that a process can always ptrace its direct children, which is enough
	// for testing purposes.
	struct __user_cap_header_struct cap_hdr = {};
	struct __user_cap_data_struct cap_data[2] = {};
	cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
	cap_hdr.pid = getpid();
	if (syscall(SYS_capget, &cap_hdr, &cap_data))
		fail("capget failed");
	cap_data[0].effective &= ~(1 << CAP_SYS_PTRACE);
	cap_data[0].permitted &= ~(1 << CAP_SYS_PTRACE);
	cap_data[0].inheritable &= ~(1 << CAP_SYS_PTRACE);
	if (syscall(SYS_capset, &cap_hdr, &cap_data))
		fail("capset failed");

	loop();
	doexit(1);
}

static int do_sandbox_namespace(void)
{
	int pid;

	setup_common();
	real_uid = getuid();
	real_gid = getgid();
	mprotect(sandbox_stack, 4096, PROT_NONE); // to catch stack underflows
	pid = clone(namespace_sandbox_proc, &sandbox_stack[sizeof(sandbox_stack) - 64],
		    CLONE_NEWUSER | CLONE_NEWPID, 0);
	return wait_for_loop(pid);
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT && SYZ_USE_TMP_DIR
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#define FS_IOC_SETFLAGS _IOW('f', 2, long)

// One does not simply remove a directory.
// There can be mounts, so we need to try to umount.
// Moreover, a mount can be mounted several times, so we need to try to umount in a loop.
// Moreover, after umount a dir can become non-empty again, so we need another loop.
// Moreover, a mount can be re-mounted as read-only and then we will fail to make a dir empty.
static void remove_dir(const char* dir)
{
	DIR* dp;
	struct dirent* ep;
	int iter = 0;
retry:
	while (umount2(dir, MNT_DETACH) == 0) {
		debug("umount(%s)\n", dir);
	}
	dp = opendir(dir);
	if (dp == NULL) {
		if (errno == EMFILE) {
			// This happens when the test process casts prlimit(NOFILE) on us.
			// Ideally we somehow prevent test processes from messing with parent processes.
			// But full sandboxing is expensive, so let's ignore this error for now.
			exitf("opendir(%s) failed due to NOFILE, exiting", dir);
		}
		exitf("opendir(%s) failed", dir);
	}
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char filename[FILENAME_MAX];
		snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);
		// If it's 9p mount with broken transport, lstat will fail.
		// So try to umount first.
		while (umount2(filename, MNT_DETACH) == 0) {
			debug("umount(%s)\n", filename);
		}
		struct stat st;
		if (lstat(filename, &st))
			exitf("lstat(%s) failed", filename);
		if (S_ISDIR(st.st_mode)) {
			remove_dir(filename);
			continue;
		}
		int i;
		for (i = 0;; i++) {
			debug("unlink(%s)\n", filename);
			if (unlink(filename) == 0)
				break;
			if (errno == EPERM) {
				// Try to reset FS_XFLAG_IMMUTABLE.
				int fd = open(filename, O_RDONLY);
				if (fd != -1) {
					long flags = 0;
					if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0)
						debug("reset FS_XFLAG_IMMUTABLE\n");
					close(fd);
					continue;
				}
			}
			if (errno == EROFS) {
				debug("ignoring EROFS\n");
				break;
			}
			if (errno != EBUSY || i > 100)
				exitf("unlink(%s) failed", filename);
			debug("umount(%s)\n", filename);
			if (umount2(filename, MNT_DETACH))
				exitf("umount(%s) failed", filename);
		}
	}
	closedir(dp);
	int i;
	for (i = 0;; i++) {
		debug("rmdir(%s)\n", dir);
		if (rmdir(dir) == 0)
			break;
		if (i < 100) {
			if (errno == EPERM) {
				// Try to reset FS_XFLAG_IMMUTABLE.
				int fd = open(dir, O_RDONLY);
				if (fd != -1) {
					long flags = 0;
					if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0)
						debug("reset FS_XFLAG_IMMUTABLE\n");
					close(fd);
					continue;
				}
			}
			if (errno == EROFS) {
				debug("ignoring EROFS\n");
				break;
			}
			if (errno == EBUSY) {
				debug("umount(%s)\n", dir);
				if (umount2(dir, MNT_DETACH))
					exitf("umount(%s) failed", dir);
				continue;
			}
			if (errno == ENOTEMPTY) {
				if (iter < 100) {
					iter++;
					goto retry;
				}
			}
		}
		exitf("rmdir(%s) failed", dir);
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_FAULT_INJECTION
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int inject_fault(int nth)
{
	int fd;
	char buf[16];

	fd = open("/proc/thread-self/fail-nth", O_RDWR);
	// We treat errors here as temporal/non-critical because we see
	// occasional ENOENT/EACCES errors returned. It seems that fuzzer
	// somehow gets its hands to it.
	if (fd == -1)
		exitf("failed to open /proc/thread-self/fail-nth");
	sprintf(buf, "%d", nth + 1);
	if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf))
		exitf("failed to write /proc/thread-self/fail-nth");
	return fd;
}
#endif

#if SYZ_EXECUTOR
static int fault_injected(int fail_fd)
{
	char buf[16];
	int n = read(fail_fd, buf, sizeof(buf) - 1);
	if (n <= 0)
		exitf("failed to read /proc/thread-self/fail-nth");
	int res = n == 2 && buf[0] == '0' && buf[1] == '\n';
	buf[0] = '0';
	if (write(fail_fd, buf, 1) != 1)
		exitf("failed to write /proc/thread-self/fail-nth");
	close(fail_fd);
	return res;
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

static void kill_and_wait(int pid, int* status)
{
	kill(-pid, SIGKILL);
	kill(pid, SIGKILL);
	int i;
	// First, give it up to 100 ms to surrender.
	for (i = 0; i < 100; i++) {
		if (waitpid(-1, status, WNOHANG | __WALL) == pid)
			return;
		usleep(1000);
	}
	// Now, try to abort fuse connections as they cause deadlocks,
	// see Documentation/filesystems/fuse.txt for details.
	// There is no good way to figure out the right connections
	// provided that the process could use unshare(CLONE_NEWNS),
	// so we abort all.
	debug("kill is not working\n");
	DIR* dir = opendir("/sys/fs/fuse/connections");
	if (dir) {
		for (;;) {
			struct dirent* ent = readdir(dir);
			if (!ent)
				break;
			if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
				continue;
			char abort[300];
			snprintf(abort, sizeof(abort), "/sys/fs/fuse/connections/%s/abort", ent->d_name);
			int fd = open(abort, O_WRONLY);
			if (fd == -1) {
				debug("failed to open %s: %d\n", abort, errno);
				continue;
			}
			debug("aborting fuse conn %s\n", ent->d_name);
			if (write(fd, abort, 1) < 0) {
				debug("failed to abort: %d\n", errno);
			}
			close(fd);
		}
		closedir(dir);
	} else {
		debug("failed to open /sys/fs/fuse/connections: %d\n", errno);
	}
	// Now, just wait, no other options.
	while (waitpid(-1, status, __WALL) != pid) {
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_ENABLE_CGROUPS || SYZ_RESET_NET_NAMESPACE)
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SYZ_HAVE_SETUP_LOOP 1
static void setup_loop()
{
#if SYZ_EXECUTOR || SYZ_ENABLE_CGROUPS
	int pid = getpid();
	char cgroupdir[64];
	char procs_file[128];
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/unified/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	snprintf(procs_file, sizeof(procs_file), "%s/cgroup.procs", cgroupdir);
	if (!write_file(procs_file, "%d", pid)) {
		debug("write(%s) failed: %d\n", procs_file, errno);
	}
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/cpu/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	snprintf(procs_file, sizeof(procs_file), "%s/cgroup.procs", cgroupdir);
	if (!write_file(procs_file, "%d", pid)) {
		debug("write(%s) failed: %d\n", procs_file, errno);
	}
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/net/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	snprintf(procs_file, sizeof(procs_file), "%s/cgroup.procs", cgroupdir);
	if (!write_file(procs_file, "%d", pid)) {
		debug("write(%s) failed: %d\n", procs_file, errno);
	}
#endif
#if SYZ_EXECUTOR || SYZ_RESET_NET_NAMESPACE
	checkpoint_net_namespace();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_RESET_NET_NAMESPACE || __NR_syz_mount_image || __NR_syz_read_part_table)
#define SYZ_HAVE_RESET_LOOP 1
static void reset_loop()
{
#if SYZ_EXECUTOR || __NR_syz_mount_image || __NR_syz_read_part_table
	char buf[64];
	snprintf(buf, sizeof(buf), "/dev/loop%llu", procid);
	int loopfd = open(buf, O_RDWR);
	if (loopfd != -1) {
		ioctl(loopfd, LOOP_CLR_FD, 0);
		close(loopfd);
	}
#endif
#if SYZ_EXECUTOR || SYZ_RESET_NET_NAMESPACE
	reset_net_namespace();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
#include <sys/prctl.h>

#define SYZ_HAVE_SETUP_TEST 1
static void setup_test()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
#if SYZ_EXECUTOR || SYZ_ENABLE_CGROUPS
	char cgroupdir[64];
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/unified/syz%llu", procid);
	if (symlink(cgroupdir, "./cgroup")) {
		debug("symlink(%s, ./cgroup) failed: %d\n", cgroupdir, errno);
	}
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/cpu/syz%llu", procid);
	if (symlink(cgroupdir, "./cgroup.cpu")) {
		debug("symlink(%s, ./cgroup.cpu) failed: %d\n", cgroupdir, errno);
	}
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/net/syz%llu", procid);
	if (symlink(cgroupdir, "./cgroup.net")) {
		debug("symlink(%s, ./cgroup.net) failed: %d\n", cgroupdir, errno);
	}
#endif
#if SYZ_EXECUTOR || SYZ_TUN_ENABLE
	// Read all remaining packets from tun to better
	// isolate consequently executing programs.
	flush_tun();
#endif
}

#define SYZ_HAVE_RESET_TEST 1
static void reset_test()
{
	// Keeping a 9p transport pipe open will hang the proccess dead,
	// so close all opened file descriptors.
	int fd;
	for (fd = 3; fd < 30; fd++)
		close(fd);
}
#endif
