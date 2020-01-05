// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#if SYZ_EXECUTOR
const int kExtraCoverSize = 256 << 10;
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
	syscall(SYS_futex, &ev->state, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1000000);
}

static void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0);
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
		syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts);
		if (__atomic_load_n(&ev->state, __ATOMIC_RELAXED))
			return 1;
		now = current_time_ms();
		if (now - start > timeout)
			return 0;
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT || SYZ_NET_INJECTION || SYZ_FAULT || SYZ_SANDBOX_NONE || \
    SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID ||               \
    SYZ_FAULT || SYZ_LEAK || SYZ_BINFMT_MISC || (__NR_syz_usb_connect && USB_DEBUG)
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
		debug("write(%s) failed: %d\n", file, err);
		errno = err;
		return false;
	}
	close(fd);
	return true;
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/in6.h>
#include <linux/neighbour.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>

struct nlmsg {
	char* pos;
	int nesting;
	struct nlattr* nested[8];
	char buf[1024];
};

static struct nlmsg nlmsg;

static void netlink_init(struct nlmsg* nlmsg, int typ, int flags,
			 const void* data, int size)
{
	memset(nlmsg, 0, sizeof(*nlmsg));
	struct nlmsghdr* hdr = (struct nlmsghdr*)nlmsg->buf;
	hdr->nlmsg_type = typ;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	memcpy(hdr + 1, data, size);
	nlmsg->pos = (char*)(hdr + 1) + NLMSG_ALIGN(size);
}

static void netlink_attr(struct nlmsg* nlmsg, int typ,
			 const void* data, int size)
{
	struct nlattr* attr = (struct nlattr*)nlmsg->pos;
	attr->nla_len = sizeof(*attr) + size;
	attr->nla_type = typ;
	memcpy(attr + 1, data, size);
	nlmsg->pos += NLMSG_ALIGN(attr->nla_len);
}

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
static void netlink_nest(struct nlmsg* nlmsg, int typ)
{
	struct nlattr* attr = (struct nlattr*)nlmsg->pos;
	attr->nla_type = typ;
	nlmsg->pos += sizeof(*attr);
	nlmsg->nested[nlmsg->nesting++] = attr;
}

static void netlink_done(struct nlmsg* nlmsg)
{
	struct nlattr* attr = nlmsg->nested[--nlmsg->nesting];
	attr->nla_len = nlmsg->pos - (char*)attr;
}
#endif

static int netlink_send_ext(struct nlmsg* nlmsg, int sock,
			    uint16 reply_type, int* reply_len)
{
	if (nlmsg->pos > nlmsg->buf + sizeof(nlmsg->buf) || nlmsg->nesting)
		fail("nlmsg overflow/bad nesting");
	struct nlmsghdr* hdr = (struct nlmsghdr*)nlmsg->buf;
	hdr->nlmsg_len = nlmsg->pos - nlmsg->buf;
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	unsigned n = sendto(sock, nlmsg->buf, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (n != hdr->nlmsg_len)
		fail("short netlink write: %d/%d", n, hdr->nlmsg_len);
	n = recv(sock, nlmsg->buf, sizeof(nlmsg->buf), 0);
	if (hdr->nlmsg_type == NLMSG_DONE) {
		*reply_len = 0;
		return 0;
	}
	if (n < sizeof(struct nlmsghdr))
		fail("short netlink read: %d", n);
	if (reply_len && hdr->nlmsg_type == reply_type) {
		*reply_len = n;
		return 0;
	}
	if (n < sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr))
		fail("short netlink read: %d", n);
	if (hdr->nlmsg_type != NLMSG_ERROR)
		fail("short netlink ack: %d", hdr->nlmsg_type);
	return -((struct nlmsgerr*)(hdr + 1))->error;
}

static int netlink_send(struct nlmsg* nlmsg, int sock)
{
	return netlink_send_ext(nlmsg, sock, 0, NULL);
}

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_DEVLINK_PCI
static int netlink_next_msg(struct nlmsg* nlmsg, unsigned int offset,
			    unsigned int total_len)
{
	struct nlmsghdr* hdr = (struct nlmsghdr*)(nlmsg->buf + offset);

	if (offset == total_len || offset + hdr->nlmsg_len > total_len)
		return -1;
	return hdr->nlmsg_len;
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
static void netlink_add_device_impl(struct nlmsg* nlmsg, const char* type,
				    const char* name)
{
	struct ifinfomsg hdr;
	memset(&hdr, 0, sizeof(hdr));
	netlink_init(nlmsg, RTM_NEWLINK, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
	if (name)
		netlink_attr(nlmsg, IFLA_IFNAME, name, strlen(name));
	netlink_nest(nlmsg, IFLA_LINKINFO);
	netlink_attr(nlmsg, IFLA_INFO_KIND, type, strlen(type));
}

static void netlink_add_device(struct nlmsg* nlmsg, int sock, const char* type,
			       const char* name)
{
	netlink_add_device_impl(nlmsg, type, name);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	debug("netlink: adding device %s type %s: %s\n", name, type, strerror(err));
	(void)err;
}

static void netlink_add_veth(struct nlmsg* nlmsg, int sock, const char* name,
			     const char* peer)
{
	netlink_add_device_impl(nlmsg, "veth", name);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_nest(nlmsg, VETH_INFO_PEER);
	nlmsg->pos += sizeof(struct ifinfomsg);
	netlink_attr(nlmsg, IFLA_IFNAME, peer, strlen(peer));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	debug("netlink: adding device %s type veth peer %s: %s\n", name, peer, strerror(err));
	(void)err;
}

static void netlink_add_hsr(struct nlmsg* nlmsg, int sock, const char* name,
			    const char* slave1, const char* slave2)
{
	netlink_add_device_impl(nlmsg, "hsr", name);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	int ifindex1 = if_nametoindex(slave1);
	netlink_attr(nlmsg, IFLA_HSR_SLAVE1, &ifindex1, sizeof(ifindex1));
	int ifindex2 = if_nametoindex(slave2);
	netlink_attr(nlmsg, IFLA_HSR_SLAVE2, &ifindex2, sizeof(ifindex2));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	debug("netlink: adding device %s type hsr slave1 %s slave2 %s: %s\n",
	      name, slave1, slave2, strerror(err));
	(void)err;
}

static void netlink_add_virt_wifi(struct nlmsg* nlmsg, int sock, const char* name, const char* link)
{
	netlink_add_device_impl(nlmsg, "virt_wifi", name);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	debug("netlink: adding device %s type virt_wifi link %s: %s\n",
	      name, link, strerror(err));
	(void)err;
}

static void netlink_add_vlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link, uint16 id, uint16 proto)
{
	netlink_add_device_impl(nlmsg, "vlan", name);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_attr(nlmsg, IFLA_VLAN_ID, &id, sizeof(id));
	netlink_attr(nlmsg, IFLA_VLAN_PROTOCOL, &proto, sizeof(proto));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	debug("netlink: add %s type vlan link %s id %d: %s\n",
	      name, link, id, strerror(err));
	(void)err;
}

static void netlink_add_macvlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link)
{
	netlink_add_device_impl(nlmsg, "macvlan", name);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	uint32 mode = MACVLAN_MODE_BRIDGE;
	netlink_attr(nlmsg, IFLA_MACVLAN_MODE, &mode, sizeof(mode));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	debug("netlink: add %s type macvlan link %s mode %d: %s\n",
	      name, link, mode, strerror(err));
	(void)err;
}

#define IFLA_IPVLAN_FLAGS 2
#define IPVLAN_MODE_L3S 2
#undef IPVLAN_F_VEPA
#define IPVLAN_F_VEPA 2

static void netlink_add_ipvlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link, uint16 mode, uint16 flags)
{
	netlink_add_device_impl(nlmsg, "ipvlan", name);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_attr(nlmsg, IFLA_IPVLAN_MODE, &mode, sizeof(mode));
	netlink_attr(nlmsg, IFLA_IPVLAN_FLAGS, &flags, sizeof(flags));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	debug("netlink: add %s type ipvlan link %s mode %d: %s\n",
	      name, link, mode, strerror(err));
	(void)err;
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI
static void netlink_device_change(struct nlmsg* nlmsg, int sock, const char* name, bool up,
				  const char* master, const void* mac, int macsize,
				  const char* new_name)
{
	struct ifinfomsg hdr;
	memset(&hdr, 0, sizeof(hdr));
	if (up)
		hdr.ifi_flags = hdr.ifi_change = IFF_UP;
	hdr.ifi_index = if_nametoindex(name);
	netlink_init(nlmsg, RTM_NEWLINK, 0, &hdr, sizeof(hdr));
	if (new_name)
		netlink_attr(nlmsg, IFLA_IFNAME, new_name, strlen(new_name));
	if (master) {
		int ifindex = if_nametoindex(master);
		netlink_attr(nlmsg, IFLA_MASTER, &ifindex, sizeof(ifindex));
	}
	if (macsize)
		netlink_attr(nlmsg, IFLA_ADDRESS, mac, macsize);
	int err = netlink_send(nlmsg, sock);
	debug("netlink: device %s up master %s: %s\n", name, master, strerror(err));
	(void)err;
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION
static int netlink_add_addr(struct nlmsg* nlmsg, int sock, const char* dev,
			    const void* addr, int addrsize)
{
	struct ifaddrmsg hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.ifa_family = addrsize == 4 ? AF_INET : AF_INET6;
	hdr.ifa_prefixlen = addrsize == 4 ? 24 : 120;
	hdr.ifa_scope = RT_SCOPE_UNIVERSE;
	hdr.ifa_index = if_nametoindex(dev);
	netlink_init(nlmsg, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &hdr, sizeof(hdr));
	netlink_attr(nlmsg, IFA_LOCAL, addr, addrsize);
	netlink_attr(nlmsg, IFA_ADDRESS, addr, addrsize);
	return netlink_send(nlmsg, sock);
}

static void netlink_add_addr4(struct nlmsg* nlmsg, int sock,
			      const char* dev, const char* addr)
{
	struct in_addr in_addr;
	inet_pton(AF_INET, addr, &in_addr);
	int err = netlink_add_addr(nlmsg, sock, dev, &in_addr, sizeof(in_addr));
	debug("netlink: add addr %s dev %s: %s\n", addr, dev, strerror(err));
	(void)err;
}

static void netlink_add_addr6(struct nlmsg* nlmsg, int sock,
			      const char* dev, const char* addr)
{
	struct in6_addr in6_addr;
	inet_pton(AF_INET6, addr, &in6_addr);
	int err = netlink_add_addr(nlmsg, sock, dev, &in6_addr, sizeof(in6_addr));
	debug("netlink: add addr %s dev %s: %s\n", addr, dev, strerror(err));
	(void)err;
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_INJECTION
static void netlink_add_neigh(struct nlmsg* nlmsg, int sock, const char* name,
			      const void* addr, int addrsize, const void* mac, int macsize)
{
	struct ndmsg hdr;
	memset(&hdr, 0, sizeof(hdr));
	hdr.ndm_family = addrsize == 4 ? AF_INET : AF_INET6;
	hdr.ndm_ifindex = if_nametoindex(name);
	hdr.ndm_state = NUD_PERMANENT;
	netlink_init(nlmsg, RTM_NEWNEIGH, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
	netlink_attr(nlmsg, NDA_DST, addr, addrsize);
	netlink_attr(nlmsg, NDA_LLADDR, mac, macsize);
	int err = netlink_send(nlmsg, sock);
	debug("netlink: add neigh %s addr %d lladdr %d: %s\n",
	      name, addrsize, macsize, strerror(err));
	(void)err;
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_NET_INJECTION
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static int tunfd = -1;
static int tun_frags_enabled;

#define TUN_IFACE "syz_tun"

#define LOCAL_MAC 0xaaaaaaaaaaaa
#define REMOTE_MAC 0xaaaaaaaaaabb

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
	if (!flag_net_injection)
		return;
#endif
	tunfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
	if (tunfd == -1) {
#if SYZ_EXECUTOR
		fail("tun: can't open /dev/net/tun");
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
	char sysctl[64];
	sprintf(sysctl, "/proc/sys/net/ipv6/conf/%s/accept_dad", TUN_IFACE);
	write_file(sysctl, "0");
	// Disable IPv6 router solicitation to prevent IPv6 spam.
	// Don't panic because this is an optional config.
	sprintf(sysctl, "/proc/sys/net/ipv6/conf/%s/router_solicitations", TUN_IFACE);
	write_file(sysctl, "0");
	// There seems to be no way to disable IPv6 MTD to prevent more IPv6 spam.

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed");

	netlink_add_addr4(&nlmsg, sock, TUN_IFACE, LOCAL_IPV4);
	netlink_add_addr6(&nlmsg, sock, TUN_IFACE, LOCAL_IPV6);
	uint64 macaddr = REMOTE_MAC;
	struct in_addr in_addr;
	inet_pton(AF_INET, REMOTE_IPV4, &in_addr);
	netlink_add_neigh(&nlmsg, sock, TUN_IFACE, &in_addr, sizeof(in_addr), &macaddr, ETH_ALEN);
	struct in6_addr in6_addr;
	inet_pton(AF_INET6, REMOTE_IPV6, &in6_addr);
	netlink_add_neigh(&nlmsg, sock, TUN_IFACE, &in6_addr, sizeof(in6_addr), &macaddr, ETH_ALEN);
	macaddr = LOCAL_MAC;
	netlink_device_change(&nlmsg, sock, TUN_IFACE, true, 0, &macaddr, ETH_ALEN, NULL);
	close(sock);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_init_net_socket || SYZ_DEVLINK_PCI
const int kInitNetNsFd = 239; // see kMaxFd
#endif

#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI || SYZ_NET_DEVICES

#include <linux/genetlink.h>
#include <stdbool.h>

#define DEVLINK_FAMILY_NAME "devlink"

#define DEVLINK_CMD_PORT_GET 5
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
#define DEVLINK_CMD_RELOAD 37
#endif
#define DEVLINK_ATTR_BUS_NAME 1
#define DEVLINK_ATTR_DEV_NAME 2
#define DEVLINK_ATTR_NETDEV_NAME 7
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
#define DEVLINK_ATTR_NETNS_FD 138
#endif

static int netlink_devlink_id_get(struct nlmsg* nlmsg, int sock)
{
	struct genlmsghdr genlhdr;
	struct nlattr* attr;
	int err, n;
	uint16 id = 0;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = CTRL_CMD_GETFAMILY;
	netlink_init(nlmsg, GENL_ID_CTRL, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, CTRL_ATTR_FAMILY_NAME, DEVLINK_FAMILY_NAME, strlen(DEVLINK_FAMILY_NAME) + 1);
	err = netlink_send_ext(nlmsg, sock, GENL_ID_CTRL, &n);
	if (err) {
		debug("netlink: failed to get devlink family id: %s\n", strerror(err));
		return -1;
	}
	attr = (struct nlattr*)(nlmsg->buf + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
	for (; (char*)attr < nlmsg->buf + n; attr = (struct nlattr*)((char*)attr + NLMSG_ALIGN(attr->nla_len))) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
			id = *(uint16*)(attr + 1);
			break;
		}
	}
	if (!id) {
		debug("netlink: failed to parse message for devlink family id\n");
		return -1;
	}
	recv(sock, nlmsg->buf, sizeof(nlmsg->buf), 0); /* recv ack */

	return id;
}

#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
static void netlink_devlink_netns_move(const char* bus_name, const char* dev_name, int netns_fd)
{
	struct genlmsghdr genlhdr;
	int sock;
	int id, err;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed\n");

	id = netlink_devlink_id_get(&nlmsg, sock);
	if (id == -1)
		goto error;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = DEVLINK_CMD_RELOAD;
	netlink_init(&nlmsg, id, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, DEVLINK_ATTR_BUS_NAME, bus_name, strlen(bus_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_DEV_NAME, dev_name, strlen(dev_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_NETNS_FD, &netns_fd, sizeof(netns_fd));
	err = netlink_send(&nlmsg, sock);
	if (err) {
		debug("netlink: failed to move devlink instance %s/%s into network namespace: %s\n",
		      bus_name, dev_name, strerror(err));
	}
error:
	close(sock);
}
#endif

static struct nlmsg nlmsg2;

static void initialize_devlink_ports(const char* bus_name, const char* dev_name,
				     const char* netdev_prefix)
{
	struct genlmsghdr genlhdr;
	int len, total_len, id, err, offset;
	uint16 netdev_index;

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed\n");

	int rtsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rtsock == -1)
		fail("socket(AF_NETLINK) failed");

	id = netlink_devlink_id_get(&nlmsg, sock);
	if (id == -1)
		goto error;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = DEVLINK_CMD_PORT_GET;
	netlink_init(&nlmsg, id, NLM_F_DUMP, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, DEVLINK_ATTR_BUS_NAME, bus_name, strlen(bus_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_DEV_NAME, dev_name, strlen(dev_name) + 1);

	err = netlink_send_ext(&nlmsg, sock, id, &total_len);
	if (err) {
		debug("netlink: failed to get port get reply: %s\n", strerror(err));
		goto error;
	}

	offset = 0;
	netdev_index = 0;
	while ((len = netlink_next_msg(&nlmsg, offset, total_len)) != -1) {
		struct nlattr* attr = (struct nlattr*)(nlmsg.buf + offset + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
		for (; (char*)attr < nlmsg.buf + offset + len; attr = (struct nlattr*)((char*)attr + NLMSG_ALIGN(attr->nla_len))) {
			if (attr->nla_type == DEVLINK_ATTR_NETDEV_NAME) {
				char* port_name;
				char netdev_name[IFNAMSIZ];
				port_name = (char*)(attr + 1);
				snprintf(netdev_name, sizeof(netdev_name), "%s%d", netdev_prefix, netdev_index);
				netlink_device_change(&nlmsg2, rtsock, port_name, true, 0, 0, 0, netdev_name);
				break;
			}
		}
		offset += len;
		netdev_index++;
	}
error:
	close(rtsock);
	close(sock);
}

#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
#include <fcntl.h>
#include <sched.h>

static void initialize_devlink_pci(void)
{
#if SYZ_EXECUTOR
	if (!flag_devlink_pci)
		return;
#endif
	int netns = open("/proc/self/ns/net", O_RDONLY);
	if (netns == -1)
		fail("open(/proc/self/ns/net) failed");
	int ret = setns(kInitNetNsFd, 0);
	if (ret == -1)
		fail("set_ns(init_netns_fd) failed");
	netlink_devlink_netns_move("pci", "0000:00:10.0", netns);
	ret = setns(netns, 0);
	if (ret == -1)
		fail("set_ns(this_netns_fd) failed");
	close(netns);

	initialize_devlink_ports("pci", "0000:00:10.0", "netpci");
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Addresses are chosen to be in the same subnet as tun addresses.
#define DEV_IPV4 "172.20.20.%d"
#define DEV_IPV6 "fe80::%02x"
#define DEV_MAC 0x00aaaaaaaaaa

static void netdevsim_add(unsigned int addr, unsigned int port_count)
{
	char buf[16];

	sprintf(buf, "%u %u", addr, port_count);
	if (write_file("/sys/bus/netdevsim/new_device", buf)) {
		snprintf(buf, sizeof(buf), "netdevsim%d", addr);
		initialize_devlink_ports("netdevsim", buf, "netdevsim");
	}
}

// We test in a separate namespace, which does not have any network devices initially (even lo).
// Create/up as many as we can.
static void initialize_netdevices(void)
{
#if SYZ_EXECUTOR
	if (!flag_net_devices)
		return;
#endif
	// TODO: add the following devices:
	// - vxlan
	// - macsec
	// - ipip
	// - lowpan
	// - ipoib
	// - geneve
	// - vrf
	// - rmnet
	// - openvswitch
	// Naive attempts to add devices of these types fail with various errors.
	// Also init namespace contains the following devices (which presumably can't be
	// created in non-init namespace), can we use them somehow?
	// - ifb0/1
	// - wpan0/1
	// - hwsim0
	// - teql0
	// - eql
	char netdevsim[16];
	sprintf(netdevsim, "netdevsim%d", (int)procid);
	struct {
		const char* type;
		const char* dev;
	} devtypes[] = {
	    // Note: ip6erspan device can't be added if ip6gretap exists in the same namespace.
	    {"ip6gretap", "ip6gretap0"},
	    {"bridge", "bridge0"},
	    {"vcan", "vcan0"},
	    {"bond", "bond0"},
	    {"team", "team0"},
	    {"dummy", "dummy0"},
	    {"nlmon", "nlmon0"},
	    {"caif", "caif0"},
	    {"batadv", "batadv0"},
	    // Note: this adds vxcan0/vxcan1 pair, similar to veth (creating vxcan0 would fail).
	    {"vxcan", "vxcan1"},
	    // Note: netdevsim devices can't have the same name even in different namespaces.
	    {"netdevsim", netdevsim},
	    // This adds connected veth0 and veth1 devices.
	    {"veth", 0},
	    {"xfrm", "xfrm0"},
	};
	const char* devmasters[] = {"bridge", "bond", "team"};
	// If you extend this array, also update netdev_addr_id in vnet.txt.
	struct {
		const char* name;
		int macsize;
		bool noipv6;
	} devices[] = {
	    {"lo", ETH_ALEN},
	    {"sit0", 0},
	    {"bridge0", ETH_ALEN},
	    {"vcan0", 0, true},
	    {"tunl0", 0},
	    {"gre0", 0},
	    {"gretap0", ETH_ALEN},
	    {"ip_vti0", 0},
	    {"ip6_vti0", 0},
	    {"ip6tnl0", 0},
	    {"ip6gre0", 0},
	    {"ip6gretap0", ETH_ALEN},
	    {"erspan0", ETH_ALEN},
	    {"bond0", ETH_ALEN},
	    {"veth0", ETH_ALEN},
	    {"veth1", ETH_ALEN},
	    {"team0", ETH_ALEN},
	    {"veth0_to_bridge", ETH_ALEN},
	    {"veth1_to_bridge", ETH_ALEN},
	    {"veth0_to_bond", ETH_ALEN},
	    {"veth1_to_bond", ETH_ALEN},
	    {"veth0_to_team", ETH_ALEN},
	    {"veth1_to_team", ETH_ALEN},
	    {"veth0_to_hsr", ETH_ALEN},
	    {"veth1_to_hsr", ETH_ALEN},
	    {"hsr0", 0},
	    {"dummy0", ETH_ALEN},
	    {"nlmon0", 0},
	    {"vxcan0", 0, true},
	    {"vxcan1", 0, true},
	    {"caif0", ETH_ALEN}, // TODO: up'ing caif fails with ENODEV
	    {"batadv0", ETH_ALEN},
	    {netdevsim, ETH_ALEN},
	    {"xfrm0", ETH_ALEN},
	    {"veth0_virt_wifi", ETH_ALEN},
	    {"veth1_virt_wifi", ETH_ALEN},
	    {"virt_wifi0", ETH_ALEN},
	    {"veth0_vlan", ETH_ALEN},
	    {"veth1_vlan", ETH_ALEN},
	    {"vlan0", ETH_ALEN},
	    {"vlan1", ETH_ALEN},
	    {"macvlan0", ETH_ALEN},
	    {"macvlan1", ETH_ALEN},
	    {"ipvlan0", ETH_ALEN},
	    {"ipvlan1", ETH_ALEN},
	};
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed");
	unsigned i;
	for (i = 0; i < sizeof(devtypes) / sizeof(devtypes[0]); i++)
		netlink_add_device(&nlmsg, sock, devtypes[i].type, devtypes[i].dev);
	// This creates connected bridge/bond/team_slave devices of type veth,
	// and makes them slaves of bridge/bond/team devices, respectively.
	// Note: slave devices don't need MAC/IP addresses, only master devices.
	//       veth0_to_* is not slave devices, which still need ip addresses.
	for (i = 0; i < sizeof(devmasters) / (sizeof(devmasters[0])); i++) {
		char master[32], slave0[32], veth0[32], slave1[32], veth1[32];
		sprintf(slave0, "%s_slave_0", devmasters[i]);
		sprintf(veth0, "veth0_to_%s", devmasters[i]);
		netlink_add_veth(&nlmsg, sock, slave0, veth0);
		sprintf(slave1, "%s_slave_1", devmasters[i]);
		sprintf(veth1, "veth1_to_%s", devmasters[i]);
		netlink_add_veth(&nlmsg, sock, slave1, veth1);
		sprintf(master, "%s0", devmasters[i]);
		netlink_device_change(&nlmsg, sock, slave0, false, master, 0, 0, NULL);
		netlink_device_change(&nlmsg, sock, slave1, false, master, 0, 0, NULL);
	}
	// bond/team_slave_* will set up automatically when set their master.
	// But bridge_slave_* need to set up manually.
	netlink_device_change(&nlmsg, sock, "bridge_slave_0", true, 0, 0, 0, NULL);
	netlink_device_change(&nlmsg, sock, "bridge_slave_1", true, 0, 0, 0, NULL);

	// Setup hsr device (slightly different from what we do for devmasters).
	netlink_add_veth(&nlmsg, sock, "hsr_slave_0", "veth0_to_hsr");
	netlink_add_veth(&nlmsg, sock, "hsr_slave_1", "veth1_to_hsr");
	netlink_add_hsr(&nlmsg, sock, "hsr0", "hsr_slave_0", "hsr_slave_1");
	netlink_device_change(&nlmsg, sock, "hsr_slave_0", true, 0, 0, 0, NULL);
	netlink_device_change(&nlmsg, sock, "hsr_slave_1", true, 0, 0, 0, NULL);

	netlink_add_veth(&nlmsg, sock, "veth0_virt_wifi", "veth1_virt_wifi");
	netlink_add_virt_wifi(&nlmsg, sock, "virt_wifi0", "veth1_virt_wifi");

	netlink_add_veth(&nlmsg, sock, "veth0_vlan", "veth1_vlan");
	netlink_add_vlan(&nlmsg, sock, "vlan0", "veth0_vlan", 0, htons(ETH_P_8021Q));
	netlink_add_vlan(&nlmsg, sock, "vlan1", "veth0_vlan", 1, htons(ETH_P_8021AD));
	netlink_add_macvlan(&nlmsg, sock, "macvlan0", "veth1_vlan");
	netlink_add_macvlan(&nlmsg, sock, "macvlan1", "veth1_vlan");
	netlink_add_ipvlan(&nlmsg, sock, "ipvlan0", "veth0_vlan", IPVLAN_MODE_L2, 0);
	netlink_add_ipvlan(&nlmsg, sock, "ipvlan1", "veth0_vlan", IPVLAN_MODE_L3S, IPVLAN_F_VEPA);

	netdevsim_add((int)procid, 4); // Number of port is in sync with value in sys/linux/socket_netlink_generic_devlink.txt

	for (i = 0; i < sizeof(devices) / (sizeof(devices[0])); i++) {
		// Assign some unique address to devices. Some devices won't up without this.
		// Shift addresses by 10 because 0 subnet address can mean special things.
		char addr[32];
		sprintf(addr, DEV_IPV4, i + 10);
		netlink_add_addr4(&nlmsg, sock, devices[i].name, addr);
		if (!devices[i].noipv6) {
			sprintf(addr, DEV_IPV6, i + 10);
			netlink_add_addr6(&nlmsg, sock, devices[i].name, addr);
		}
		uint64 macaddr = DEV_MAC + ((i + 10ull) << 40);
		netlink_device_change(&nlmsg, sock, devices[i].name, true, 0, &macaddr, devices[i].macsize, NULL);
	}
	close(sock);
}

// Same as initialize_netdevices, but called in init net namespace.
static void initialize_netdevices_init(void)
{
#if SYZ_EXECUTOR
	if (!flag_net_devices)
		return;
#endif
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed");
	struct {
		const char* type;
		int macsize;
		bool noipv6;
		bool noup;
	} devtypes[] = {
	    // NETROM device, see net/netrom/{af_netrom,nr_dev}.c
	    {"nr", 7, true},
	    // ROSE device, see net/rose/{af_rose,rose_dev}.c
	    // We don't up it yet because it crashes kernel right away:
	    // https://groups.google.com/d/msg/syzkaller/v-4B3zoBC-4/02SCKEzJBwAJ
	    {"rose", 5, true, true},
	};
	unsigned i;
	for (i = 0; i < sizeof(devtypes) / sizeof(devtypes[0]); i++) {
		char dev[32], addr[32];
		sprintf(dev, "%s%d", devtypes[i].type, (int)procid);
		// Note: syscall descriptions know these addresses.
		sprintf(addr, "172.30.%d.%d", i, (int)procid + 1);
		netlink_add_addr4(&nlmsg, sock, dev, addr);
		if (!devtypes[i].noipv6) {
			sprintf(addr, "fe88::%02x:%02x", i, (int)procid + 1);
			netlink_add_addr6(&nlmsg, sock, dev, addr);
		}
		int macsize = devtypes[i].macsize;
		uint64 macaddr = 0xbbbbbb + ((unsigned long long)i << (8 * (macsize - 2))) +
				 (procid << (8 * (macsize - 1)));
		netlink_device_change(&nlmsg, sock, dev, !devtypes[i].noup, 0, &macaddr, macsize, NULL);
	}
	close(sock);
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_INJECTION && (__NR_syz_extract_tcp_res || SYZ_REPEAT)
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

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet && SYZ_NET_INJECTION
#include <stdbool.h>
#include <sys/uio.h>

#define MAX_FRAGS 4
struct vnet_fragmentation {
	uint32 full;
	uint32 count;
	uint32 frags[MAX_FRAGS];
};

static long syz_emit_ethernet(volatile long a0, volatile long a1, volatile long a2)
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

#if SYZ_EXECUTOR || SYZ_REPEAT && SYZ_NET_INJECTION
static void flush_tun()
{
#if SYZ_EXECUTOR
	if (!flag_net_injection)
		return;
#endif
	char data[1000];
	while (read_tun(&data[0], sizeof(data)) != -1) {
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_extract_tcp_res && SYZ_NET_INJECTION
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

static long syz_extract_tcp_res(volatile long a0, volatile long a1, volatile long a2)
{
	// syz_extract_tcp_res(res ptr[out, tcp_resources], seq_inc int32, ack_inc int32)

	if (tunfd < 0)
		return (uintptr_t)-1;

	// We just need this to be large enough to hold headers that we parse (ethernet/ip/tcp).
	// Rest of the packet (if any) will be silently truncated which is fine.
	char data[1000];
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

#if SYZ_EXECUTOR || SYZ_CLOSE_FDS || __NR_syz_usb_connect
#define MAX_FDS 30
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_connect
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common_usb.h"
#endif

#if SYZ_EXECUTOR || __NR_syz_open_dev
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static long syz_open_dev(volatile long a0, volatile long a1, volatile long a2)
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

static long syz_open_procfs(volatile long a0, volatile long a1)
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

static long syz_open_pts(volatile long a0, volatile long a1)
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
#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID
#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// syz_init_net_socket opens a socket in init net namespace.
// Used for families that can only be created in init net namespace.
static long syz_init_net_socket(volatile long domain, volatile long type, volatile long proto)
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
static long syz_init_net_socket(volatile long domain, volatile long type, volatile long proto)
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

static long syz_genetlink_get_family_id(volatile long name)
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
#define sys_memfd_create 356
#elif GOARCH_amd64
#define sys_memfd_create 319
#elif GOARCH_arm
#define sys_memfd_create 385
#elif GOARCH_arm64
#define sys_memfd_create 279
#elif GOARCH_ppc64le
#define sys_memfd_create 360
#elif GOARCH_mips64le
#define sys_memfd_create 314
#endif

static unsigned long fs_image_segment_check(unsigned long size, unsigned long nsegs, long segments)
{
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
	return size;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_read_part_table
// syz_read_part_table(size intptr, nsegs len[segments], segments ptr[in, array[fs_image_segment]])
static long syz_read_part_table(volatile unsigned long size, volatile unsigned long nsegs, volatile long segments)
{
	char loopname[64], linkname[64];
	int loopfd, err = 0, res = -1;
	unsigned long i, j;
	NONFAILING(size = fs_image_segment_check(size, nsegs, segments));
	int memfd = syscall(sys_memfd_create, "syz_read_part_table", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (ftruncate(memfd, size)) {
		err = errno;
		goto error_close_memfd;
	}
	for (i = 0; i < nsegs; i++) {
		struct fs_image_segment* segs = (struct fs_image_segment*)segments;
		int res1 = 0;
		NONFAILING(res1 = pwrite(memfd, segs[i].data, segs[i].size, segs[i].offset));
		if (res1 < 0) {
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
static long syz_mount_image(volatile long fsarg, volatile long dir, volatile unsigned long size, volatile unsigned long nsegs, volatile long segments, volatile long flags, volatile long optsarg)
{
	char loopname[64], fs[32], opts[256];
	int loopfd, err = 0, res = -1;
	unsigned long i;

	NONFAILING(size = fs_image_segment_check(size, nsegs, segments));
	int memfd = syscall(sys_memfd_create, "syz_mount_image", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (ftruncate(memfd, size)) {
		err = errno;
		goto error_close_memfd;
	}
	for (i = 0; i < nsegs; i++) {
		struct fs_image_segment* segs = (struct fs_image_segment*)segments;
		int res1 = 0;
		NONFAILING(res1 = pwrite(memfd, segs[i].data, segs[i].size, segs[i].offset));
		if (res1 < 0) {
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

#if GOARCH_amd64
#include "common_kvm_amd64.h"
#elif GOARCH_arm64
#include "common_kvm_arm64.h"
#else
static long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	return 0;
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_NET_RESET
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/net.h>

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

// ebtables.h is broken too:
// ebtables.h: In function ‘ebt_entry_target* ebt_get_target(ebt_entry*)’:
// ebtables.h:197:19: error: invalid conversion from ‘void*’ to ‘ebt_entry_target*’

#define NF_BR_NUMHOOKS 6
#define EBT_TABLE_MAXNAMELEN 32
#define EBT_CHAIN_MAXNAMELEN 32
#define EBT_BASE_CTL 128
#define EBT_SO_SET_ENTRIES (EBT_BASE_CTL)
#define EBT_SO_GET_INFO (EBT_BASE_CTL)
#define EBT_SO_GET_ENTRIES (EBT_SO_GET_INFO + 1)
#define EBT_SO_GET_INIT_INFO (EBT_SO_GET_ENTRIES + 1)
#define EBT_SO_GET_INIT_ENTRIES (EBT_SO_GET_INIT_INFO + 1)

struct ebt_replace {
	char name[EBT_TABLE_MAXNAMELEN];
	unsigned int valid_hooks;
	unsigned int nentries;
	unsigned int entries_size;
	struct ebt_entries* hook_entry[NF_BR_NUMHOOKS];
	unsigned int num_counters;
	struct ebt_counter* counters;
	char* entries;
};

struct ebt_entries {
	unsigned int distinguisher;
	char name[EBT_CHAIN_MAXNAMELEN];
	unsigned int counter_offset;
	int policy;
	unsigned int nentries;
	char data[0] __attribute__((aligned(__alignof__(struct ebt_replace))));
};

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
	if (!flag_net_reset || flag_sandbox_setuid)
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
	if (!flag_net_reset || flag_sandbox_setuid)
		return;
#endif
	reset_ebtables();
	reset_arptables();
	reset_iptables(ipv4_tables, sizeof(ipv4_tables) / sizeof(ipv4_tables[0]), AF_INET, SOL_IP);
	reset_iptables(ipv6_tables, sizeof(ipv6_tables) / sizeof(ipv6_tables[0]), AF_INET6, SOL_IPV6);
}
#endif

#if SYZ_EXECUTOR || (SYZ_CGROUPS && (SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID))
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

static void setup_cgroups()
{
#if SYZ_EXECUTOR
	if (!flag_cgroups)
		return;
#endif
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
	write_file("/syzcgroup/unified/cgroup.subtree_control", "+cpu +memory +io +pids +rdma");
	if (mkdir("/syzcgroup/cpu", 0777)) {
		debug("mkdir(/syzcgroup/cpu) failed: %d\n", errno);
	}
	if (mount("none", "/syzcgroup/cpu", "cgroup", 0, "cpuset,cpuacct,perf_event,hugetlb")) {
		debug("mount(cgroup cpu) failed: %d\n", errno);
	}
	write_file("/syzcgroup/cpu/cgroup.clone_children", "1");
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

#if SYZ_EXECUTOR || SYZ_REPEAT
static void setup_cgroups_loop()
{
#if SYZ_EXECUTOR
	if (!flag_cgroups)
		return;
#endif
	int pid = getpid();
	char file[128];
	char cgroupdir[64];
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/unified/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	// Restrict number of pids per test process to prevent fork bombs.
	// We have up to 16 threads + main process + loop.
	// 32 pids should be enough for everyone.
	snprintf(file, sizeof(file), "%s/pids.max", cgroupdir);
	write_file(file, "32");
	// Restrict memory consumption.
	// We have some syscalls that inherently consume lots of memory,
	// e.g. mounting some filesystem images requires at least 128MB
	// image in memory. We restrict RLIMIT_AS to 200MB. Here we gradually
	// increase low/high/max limits to make things more interesting.
	// Also this takes into account KASAN quarantine size.
	// If the limit is lower than KASAN quarantine size, then it can happen
	// so that we kill the process, but all of its memory is in quarantine
	// and is still accounted against memcg. As the result memcg won't
	// allow to allocate any memory in the parent and in the new test process.
	// The current limit of 300MB supports up to 9.6GB RAM (quarantine is 1/32).
	snprintf(file, sizeof(file), "%s/memory.low", cgroupdir);
	write_file(file, "%d", 298 << 20);
	snprintf(file, sizeof(file), "%s/memory.high", cgroupdir);
	write_file(file, "%d", 299 << 20);
	snprintf(file, sizeof(file), "%s/memory.max", cgroupdir);
	write_file(file, "%d", 300 << 20);
	// Setup some v1 groups to make things more interesting.
	snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
	write_file(file, "%d", pid);
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/cpu/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
	write_file(file, "%d", pid);
	snprintf(cgroupdir, sizeof(cgroupdir), "/syzcgroup/net/syz%llu", procid);
	if (mkdir(cgroupdir, 0777)) {
		debug("mkdir(%s) failed: %d\n", cgroupdir, errno);
	}
	snprintf(file, sizeof(file), "%s/cgroup.procs", cgroupdir);
	write_file(file, "%d", pid);
}

static void setup_cgroups_test()
{
#if SYZ_EXECUTOR
	if (!flag_cgroups)
		return;
#endif
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
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NAMESPACE
void initialize_cgroups()
{
#if SYZ_EXECUTOR
	if (!flag_cgroups)
		return;
#endif
	if (mkdir("./syz-tmp/newroot/syzcgroup", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/unified", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/cpu", 0700))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/syzcgroup/net", 0700))
		fail("mkdir failed");
	unsigned bind_mount_flags = MS_BIND | MS_REC | MS_PRIVATE;
	if (mount("/syzcgroup/unified", "./syz-tmp/newroot/syzcgroup/unified", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup2, MS_BIND) failed: %d\n", errno);
	}
	if (mount("/syzcgroup/cpu", "./syz-tmp/newroot/syzcgroup/cpu", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup/cpu, MS_BIND) failed: %d\n", errno);
	}
	if (mount("/syzcgroup/net", "./syz-tmp/newroot/syzcgroup/net", NULL, bind_mount_flags, NULL)) {
		debug("mount(cgroup/net, MS_BIND) failed: %d\n", errno);
	}
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID
#include <errno.h>
#include <sys/mount.h>

static void setup_common()
{
	if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
		debug("mount(fusectl) failed: %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_CGROUPS
	setup_cgroups();
#endif
}

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

#if SYZ_EXECUTOR || __NR_syz_init_net_socket || SYZ_DEVLINK_PCI
	int netns = open("/proc/self/ns/net", O_RDONLY);
	if (netns == -1)
		fail("open(/proc/self/ns/net) failed");
	if (dup2(netns, kInitNetNsFd) < 0)
		fail("dup2(netns, kInitNetNsFd) failed");
	close(netns);
#endif

	struct rlimit rlim;
#if SYZ_EXECUTOR
	rlim.rlim_cur = rlim.rlim_max = (200 << 20) +
					(kMaxThreads * kCoverSize + kExtraCoverSize) * sizeof(void*);
#else
	rlim.rlim_cur = rlim.rlim_max = (200 << 20);
#endif
	setrlimit(RLIMIT_AS, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 32 << 20;
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
	// These sysctl's restrict ipc resource usage (by default it's possible
	// to eat all system memory by creating e.g. lots of large sem sets).
	// These sysctl's are per-namespace, so we need to set them inside
	// of the test ipc namespace (after CLONE_NEWIPC).
	typedef struct {
		const char* name;
		const char* value;
	} sysctl_t;
	static const sysctl_t sysctls[] = {
	    {"/proc/sys/kernel/shmmax", "16777216"},
	    {"/proc/sys/kernel/shmall", "536870912"},
	    {"/proc/sys/kernel/shmmni", "1024"},
	    {"/proc/sys/kernel/msgmax", "8192"},
	    {"/proc/sys/kernel/msgmni", "1024"},
	    {"/proc/sys/kernel/msgmnb", "1024"},
	    {"/proc/sys/kernel/sem", "1024 1048576 500 1024"},
	};
	unsigned i;
	for (i = 0; i < sizeof(sysctls) / sizeof(sysctls[0]); i++)
		write_file(sysctls[i].name, sysctls[i].value);
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

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_NAMESPACE
#include <linux/capability.h>

static void drop_caps(void)
{
	struct __user_cap_header_struct cap_hdr = {};
	struct __user_cap_data_struct cap_data[2] = {};
	cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
	cap_hdr.pid = getpid();
	if (syscall(SYS_capget, &cap_hdr, &cap_data))
		fail("capget failed");
	// Drop CAP_SYS_PTRACE so that test processes can't attach to parent processes.
	// Previously it lead to hangs because the loop process stopped due to SIGSTOP.
	// Note that a process can always ptrace its direct children, which is enough for testing purposes.
	//
	// A process with CAP_SYS_NICE can bring kernel down by asking for too high SCHED_DEADLINE priority,
	// as the result rcu and other system services that use kernel threads will stop functioning.
	// Some parameters for SCHED_DEADLINE should be OK, but we don't have means to enforce
	// values of indirect syscall arguments. Peter Zijlstra proposed sysctl_deadline_period_{min,max}
	// which could be used to enfore safe limits without droppping CAP_SYS_NICE, but we don't have it yet.
	// See the following bug for details:
	// https://groups.google.com/forum/#!topic/syzkaller-bugs/G6Wl_PKPIWI
	const int drop = (1 << CAP_SYS_PTRACE) | (1 << CAP_SYS_NICE);
	cap_data[0].effective &= ~drop;
	cap_data[0].permitted &= ~drop;
	cap_data[0].inheritable &= ~drop;
	if (syscall(SYS_capset, &cap_hdr, &cap_data))
		fail("capset failed");
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
	drop_caps();
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices_init();
#endif
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
	initialize_devlink_pci();
#endif
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
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

#define SYZ_HAVE_SANDBOX_SETUID 1
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
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices_init();
#endif
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
	initialize_devlink_pci();
#endif
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
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

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices_init();
#endif
	// CLONE_NEWNET must always happen before tun setup,
	// because we want the tun device in the test namespace.
	if (unshare(CLONE_NEWNET))
		fail("unshare(CLONE_NEWNET)");
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
	initialize_devlink_pci();
#endif
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	// We setup tun here as it needs to be in the test net namespace,
	// which in turn needs to be in the test user namespace.
	// However, IFF_NAPI_FRAGS will fail as we are not root already.
	// TODO: we should create tun in the init net namespace and use setns
	// to move it to the target namespace.
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
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
#if SYZ_EXECUTOR || SYZ_CGROUPS
	initialize_cgroups();
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
	drop_caps();

	loop();
	doexit(1);
}

#define SYZ_HAVE_SANDBOX_NAMESPACE 1
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

#if SYZ_EXECUTOR || SYZ_SANDBOX_ANDROID
#include <fcntl.h> // open(2)
#include <grp.h> // setgroups
#include <sys/xattr.h> // setxattr, getxattr

#define AID_NET_BT_ADMIN 3001
#define AID_NET_BT 3002
#define AID_INET 3003
#define AID_EVERYBODY 9997
#define AID_APP 10000

#define UNTRUSTED_APP_UID AID_APP + 999
#define UNTRUSTED_APP_GID AID_APP + 999

const char* SELINUX_CONTEXT_UNTRUSTED_APP = "u:r:untrusted_app:s0:c512,c768";
const char* SELINUX_LABEL_APP_DATA_FILE = "u:object_r:app_data_file:s0:c512,c768";
const char* SELINUX_CONTEXT_FILE = "/proc/thread-self/attr/current";
const char* SELINUX_XATTR_NAME = "security.selinux";

const gid_t UNTRUSTED_APP_GROUPS[] = {UNTRUSTED_APP_GID, AID_NET_BT_ADMIN, AID_NET_BT, AID_INET, AID_EVERYBODY};
const size_t UNTRUSTED_APP_NUM_GROUPS = sizeof(UNTRUSTED_APP_GROUPS) / sizeof(UNTRUSTED_APP_GROUPS[0]);

// Similar to libselinux getcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void syz_getcon(char* context, size_t context_size)
{
	int fd = open(SELINUX_CONTEXT_FILE, O_RDONLY);

	if (fd < 0)
		fail("getcon: Couldn't open %s", SELINUX_CONTEXT_FILE);

	ssize_t nread = read(fd, context, context_size);

	close(fd);

	if (nread <= 0)
		fail("getcon: Failed to read from %s", SELINUX_CONTEXT_FILE);

	// The contents of the context file MAY end with a newline
	// and MAY not have a null terminator.  Handle this here.
	if (context[nread - 1] == '\n')
		context[nread - 1] = '\0';
}

// Similar to libselinux setcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void syz_setcon(const char* context)
{
	char new_context[512];

	// Attempt to write the new context
	int fd = open(SELINUX_CONTEXT_FILE, O_WRONLY);

	if (fd < 0)
		fail("setcon: Could not open %s", SELINUX_CONTEXT_FILE);

	ssize_t bytes_written = write(fd, context, strlen(context));

	// N.B.: We cannot reuse this file descriptor, since the target SELinux context
	//       may not be able to read from it.
	close(fd);

	if (bytes_written != (ssize_t)strlen(context))
		fail("setcon: Could not write entire context.  Wrote %zi, expected %zu", bytes_written, strlen(context));

	// Validate the transition by checking the context
	syz_getcon(new_context, sizeof(new_context));

	if (strcmp(context, new_context) != 0)
		fail("setcon: Failed to change to %s, context is %s", context, new_context);
}

// Similar to libselinux getfilecon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static int syz_getfilecon(const char* path, char* context, size_t context_size)
{
	int length = getxattr(path, SELINUX_XATTR_NAME, context, context_size);

	if (length == -1)
		fail("getfilecon: getxattr failed");

	return length;
}

// Similar to libselinux setfilecon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void syz_setfilecon(const char* path, const char* context)
{
	char new_context[512];

	if (setxattr(path, SELINUX_XATTR_NAME, context, strlen(context) + 1, 0) != 0)
		fail("setfilecon: setxattr failed");

	if (syz_getfilecon(path, new_context, sizeof(new_context)) <= 0)
		fail("setfilecon: getfilecon failed");

	if (strcmp(context, new_context) != 0)
		fail("setfilecon: could not set context to %s, currently %s", context, new_context);
}

#define SYZ_HAVE_SANDBOX_ANDROID 1
static int do_sandbox_android(void)
{
	setup_common();
	sandbox_common();

	if (chown(".", UNTRUSTED_APP_UID, UNTRUSTED_APP_UID) != 0)
		fail("chmod failed");

	if (setgroups(UNTRUSTED_APP_NUM_GROUPS, UNTRUSTED_APP_GROUPS) != 0)
		fail("setgroups failed");

	if (setresgid(UNTRUSTED_APP_GID, UNTRUSTED_APP_GID, UNTRUSTED_APP_GID) != 0)
		fail("setresgid failed");

	if (setresuid(UNTRUSTED_APP_UID, UNTRUSTED_APP_UID, UNTRUSTED_APP_UID) != 0)
		fail("setresuid failed");

	syz_setfilecon(".", SELINUX_LABEL_APP_DATA_FILE);
	syz_setcon(SELINUX_CONTEXT_UNTRUSTED_APP);

#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	// Note: sandbox_android does not unshare net namespace.
	initialize_netdevices_init();
	initialize_netdevices();
#endif

	loop();
	doexit(1);
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
			if (unlink(filename) == 0)
				break;
			if (errno == EPERM) {
				// Try to reset FS_XFLAG_IMMUTABLE.
				int fd = open(filename, O_RDONLY);
				if (fd != -1) {
					long flags = 0;
					if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0) {
						debug("reset FS_XFLAG_IMMUTABLE\n");
					}
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
		if (rmdir(dir) == 0)
			break;
		if (i < 100) {
			if (errno == EPERM) {
				// Try to reset FS_XFLAG_IMMUTABLE.
				int fd = open(dir, O_RDONLY);
				if (fd != -1) {
					long flags = 0;
					if (ioctl(fd, FS_IOC_SETFLAGS, &flags) == 0) {
						debug("reset FS_XFLAG_IMMUTABLE\n");
					}
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

#if SYZ_EXECUTOR || SYZ_FAULT
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int inject_fault(int nth)
{
	int fd;
	fd = open("/proc/thread-self/fail-nth", O_RDWR);
	// We treat errors here as temporal/non-critical because we see
	// occasional ENOENT/EACCES errors returned. It seems that fuzzer
	// somehow gets its hands to it.
	if (fd == -1)
		exitf("failed to open /proc/thread-self/fail-nth");
	char buf[16];
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

#if SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_CGROUPS || SYZ_NET_RESET)
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SYZ_HAVE_SETUP_LOOP 1
static void setup_loop()
{
#if SYZ_EXECUTOR || SYZ_CGROUPS
	setup_cgroups_loop();
#endif
#if SYZ_EXECUTOR || SYZ_NET_RESET
	checkpoint_net_namespace();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_NET_RESET || __NR_syz_mount_image || __NR_syz_read_part_table)
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
#if SYZ_EXECUTOR || SYZ_NET_RESET
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
#if SYZ_EXECUTOR || SYZ_CGROUPS
	setup_cgroups_test();
#endif
	// It's the leaf test process we want to be always killed first.
	write_file("/proc/self/oom_score_adj", "1000");
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	// Read all remaining packets from tun to better
	// isolate consequently executing programs.
	flush_tun();
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_CLOSE_FDS
#define SYZ_HAVE_CLOSE_FDS 1
static void close_fds()
{
#if SYZ_EXECUTOR
	if (!flag_close_fds)
		return;
#endif
	// Keeping a 9p transport pipe open will hang the proccess dead,
	// so close all opened file descriptors.
	// Also close all USB emulation descriptors to trigger exit from USB
	// event loop to collect coverage.
	int fd;
	for (fd = 3; fd < MAX_FDS; fd++)
		close(fd);
}
#endif

#if SYZ_EXECUTOR || SYZ_FAULT
#include <errno.h>

static void setup_fault()
{
	static struct {
		const char* file;
		const char* val;
		bool fatal;
	} files[] = {
	    {"/sys/kernel/debug/failslab/ignore-gfp-wait", "N", true},
	    // These are enabled by separate configs (e.g. CONFIG_FAIL_FUTEX)
	    // and we did not check all of them in host.checkFaultInjection, so we ignore errors.
	    {"/sys/kernel/debug/fail_futex/ignore-private", "N", false},
	    {"/sys/kernel/debug/fail_page_alloc/ignore-gfp-highmem", "N", false},
	    {"/sys/kernel/debug/fail_page_alloc/ignore-gfp-wait", "N", false},
	    {"/sys/kernel/debug/fail_page_alloc/min-order", "0", false},
	};
	unsigned i;
	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (!write_file(files[i].file, files[i].val)) {
			debug("failed to write %s: %d\n", files[i].file, errno);
			if (files[i].fatal)
				fail("failed to write %s", files[i].file);
		}
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_LEAK
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define KMEMLEAK_FILE "/sys/kernel/debug/kmemleak"

static void setup_leak()
{
	// Flush boot leaks.
	if (!write_file(KMEMLEAK_FILE, "scan"))
		fail("failed to write %s", KMEMLEAK_FILE);
	sleep(5); // account for MSECS_MIN_AGE
	if (!write_file(KMEMLEAK_FILE, "scan"))
		fail("failed to write %s", KMEMLEAK_FILE);
	if (!write_file(KMEMLEAK_FILE, "clear"))
		fail("failed to write %s", KMEMLEAK_FILE);
}

#define SYZ_HAVE_LEAK_CHECK 1
#if SYZ_EXECUTOR
static void check_leaks(char** frames, int nframes)
#else
static void check_leaks(void)
#endif
{
	int fd = open(KMEMLEAK_FILE, O_RDWR);
	if (fd == -1)
		fail("failed to open(\"%s\")", KMEMLEAK_FILE);
	// KMEMLEAK has false positives. To mitigate most of them, it checksums
	// potentially leaked objects, and reports them only on the next scan
	// iff the checksum does not change. Because of that we do the following
	// intricate dance:
	// Scan, sleep, scan again. At this point we can get some leaks.
	// If there are leaks, we sleep and scan again, this can remove
	// false leaks. Then, read kmemleak again. If we get leaks now, then
	// hopefully these are true positives during the previous testing cycle.
	uint64 start = current_time_ms();
	if (write(fd, "scan", 4) != 4)
		fail("failed to write(%s, \"scan\")", KMEMLEAK_FILE);
	sleep(1);
	// Account for MSECS_MIN_AGE
	// (1 second less because scanning will take at least a second).
	while (current_time_ms() - start < 4 * 1000)
		sleep(1);
	if (write(fd, "scan", 4) != 4)
		fail("failed to write(%s, \"scan\")", KMEMLEAK_FILE);
	static char buf[128 << 10];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		fail("failed to read(%s)", KMEMLEAK_FILE);
	int nleaks = 0;
	if (n != 0) {
		sleep(1);
		if (write(fd, "scan", 4) != 4)
			fail("failed to write(%s, \"scan\")", KMEMLEAK_FILE);
		if (lseek(fd, 0, SEEK_SET) < 0)
			fail("failed to lseek(%s)", KMEMLEAK_FILE);
		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0)
			fail("failed to read(%s)", KMEMLEAK_FILE);
		buf[n] = 0;
		char* pos = buf;
		char* end = buf + n;
		while (pos < end) {
			char* next = strstr(pos + 1, "unreferenced object");
			if (!next)
				next = end;
			char prev = *next;
			*next = 0;
#if SYZ_EXECUTOR
			int f;
			for (f = 0; f < nframes; f++) {
				if (strstr(pos, frames[f]))
					break;
			}
			if (f != nframes) {
				*next = prev;
				pos = next;
				continue;
			}
#endif
			// BUG in output should be recognized by manager.
			fprintf(stderr, "BUG: memory leak\n%s\n", pos);
			*next = prev;
			pos = next;
			nleaks++;
		}
	}
	if (write(fd, "clear", 5) != 5)
		fail("failed to write(%s, \"clear\")", KMEMLEAK_FILE);
	close(fd);
	if (nleaks)
		doexit(1);
}
#endif

#if SYZ_EXECUTOR || SYZ_BINFMT_MISC
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

static void setup_binfmt_misc()
{
	if (mount(0, "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, 0)) {
		debug("mount(binfmt_misc) failed: %d\n", errno);
	}
	write_file("/proc/sys/fs/binfmt_misc/register", ":syz0:M:0:\x01::./file0:");
	write_file("/proc/sys/fs/binfmt_misc/register", ":syz1:M:1:\x02::./file0:POC");
}
#endif

#if SYZ_EXECUTOR || SYZ_KCSAN
#define KCSAN_DEBUGFS_FILE "/sys/kernel/debug/kcsan"

static void setup_kcsan()
{
	if (!write_file(KCSAN_DEBUGFS_FILE, "on"))
		fail("failed to enable KCSAN");
}

#if SYZ_EXECUTOR // currently only used by executor
static void setup_kcsan_filterlist(char** frames, int nframes, bool blacklist)
{
	int fd = open(KCSAN_DEBUGFS_FILE, O_WRONLY);
	if (fd == -1)
		fail("failed to open(\"%s\")", KCSAN_DEBUGFS_FILE);

	const char* const filtertype = blacklist ? "blacklist" : "whitelist";
	printf("adding functions to KCSAN %s: ", filtertype);
	dprintf(fd, "%s\n", filtertype);
	for (int i = 0; i < nframes; ++i) {
		printf("'%s' ", frames[i]);
		dprintf(fd, "!%s\n", frames[i]);
	}
	printf("\n");

	close(fd);
}

#define SYZ_HAVE_KCSAN 1
#endif
#endif
