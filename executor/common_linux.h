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
		if (__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
			return 1;
		now = current_time_ms();
		if (now - start > timeout)
			return 0;
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT || SYZ_NET_INJECTION || SYZ_FAULT || SYZ_SANDBOX_NONE || \
    SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID ||               \
    SYZ_FAULT || SYZ_LEAK || SYZ_BINFMT_MISC || SYZ_SYSCTL ||                           \
    ((__NR_syz_usb_connect || __NR_syz_usb_connect_ath9k) && USB_DEBUG) ||              \
    __NR_syz_usbip_server_init
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

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI || SYZ_WIFI || SYZ_802154 || \
    __NR_syz_genetlink_get_family_id || __NR_syz_80211_inject_frame || __NR_syz_80211_join_ibss || SYZ_NIC_VF
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/genetlink.h>
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
	char buf[4096];
};

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
	if (size > 0)
		memcpy(attr + 1, data, size);
	nlmsg->pos += NLMSG_ALIGN(attr->nla_len);
}

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_802154
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

#if SYZ_EXECUTOR || SYZ_NIC_VF
#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

struct vf_intf {
	char pass_thru_intf[IFNAMSIZ];
	int ppid; // used by Child
};

static struct vf_intf vf_intf;

static void find_vf_interface(void)
{
#if SYZ_EXECUTOR
	if (!flag_nic_vf)
		return;
#endif
	struct ifaddrs* addresses = NULL;
	int pid = getpid();
	int ret = 0;

	memset(&vf_intf, 0, sizeof(struct vf_intf));

	debug("Checking for VF pass-thru interface.\n");
	if (getifaddrs(&addresses) == -1) {
		debug("%s: getifaddrs() failed.\n", __func__);
		return;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (fd < 0) {
		debug("%s: socket() failed.\n", __func__);
		return;
	}
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;
	struct ifaddrs* address = addresses;

	while (address) {
		debug("ifa_name: %s\n", address->ifa_name);
		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, address->ifa_name);
		memset(&drvinfo, 0, sizeof(struct ethtool_drvinfo));
		drvinfo.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&drvinfo;
		ret = ioctl(fd, SIOCETHTOOL, &ifr);

		if (ret < 0) {
			debug("%s: ioctl() failed.\n", __func__);
		} else if (strlen(drvinfo.bus_info)) {
			debug("bus_info: %s, strlen(drvinfo.bus_info)=%zu\n",
			      drvinfo.bus_info, strlen(drvinfo.bus_info));
			if (strcmp(drvinfo.bus_info, "0000:00:11.0") == 0) {
				if (strlen(address->ifa_name) < IFNAMSIZ) {
					strncpy(vf_intf.pass_thru_intf,
						address->ifa_name, IFNAMSIZ);
					vf_intf.ppid = pid;
				} else {
					debug("%s: %d strlen(%s) >= IFNAMSIZ.\n",
					      __func__, pid, address->ifa_name);
				}
				break;
			}
		}
		address = address->ifa_next;
	}
	freeifaddrs(addresses);
	if (!vf_intf.ppid) {
		memset(&vf_intf, 0, sizeof(struct vf_intf));
		debug("%s: %d could not find VF pass-thru interface.\n", __func__, pid);
		return;
	}
	debug("%s: %d found VF pass-thru interface %s\n",
	      __func__, pid, vf_intf.pass_thru_intf);
}
#endif // SYZ_NIC_VF

#endif

static int netlink_send_ext(struct nlmsg* nlmsg, int sock,
			    uint16 reply_type, int* reply_len, bool dofail)
{
	if (nlmsg->pos > nlmsg->buf + sizeof(nlmsg->buf) || nlmsg->nesting)
		fail("nlmsg overflow/bad nesting");
	struct nlmsghdr* hdr = (struct nlmsghdr*)nlmsg->buf;
	hdr->nlmsg_len = nlmsg->pos - nlmsg->buf;
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	ssize_t n = sendto(sock, nlmsg->buf, hdr->nlmsg_len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (n != (ssize_t)hdr->nlmsg_len) {
		if (dofail)
			failmsg("netlink_send_ext: short netlink write", "wrote=%zd, want=%d", n, hdr->nlmsg_len);
		debug("netlink_send_ext: short netlink write: %zd/%d errno=%d\n", n, hdr->nlmsg_len, errno);
		return -1;
	}
	n = recv(sock, nlmsg->buf, sizeof(nlmsg->buf), 0);
	if (reply_len)
		*reply_len = 0;
	if (n < 0) {
		if (dofail)
			fail("netlink_send_ext: netlink read failed");
		debug("netlink_send_ext: netlink read failed: errno=%d\n", errno);
		return -1;
	}
	if (n < (ssize_t)sizeof(struct nlmsghdr)) {
		errno = EINVAL;
		if (dofail)
			failmsg("netlink_send_ext: short netlink read", "read=%zd", n);
		debug("netlink_send_ext: short netlink read: %zd\n", n);
		return -1;
	}
	if (hdr->nlmsg_type == NLMSG_DONE)
		return 0;
	if (reply_len && hdr->nlmsg_type == reply_type) {
		*reply_len = n;
		return 0;
	}
	if (n < (ssize_t)(sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr))) {
		errno = EINVAL;
		if (dofail)
			failmsg("netlink_send_ext: short netlink read", "read=%zd", n);
		debug("netlink_send_ext: short netlink read: %zd\n", n);
		return -1;
	}
	if (hdr->nlmsg_type != NLMSG_ERROR) {
		errno = EINVAL;
		if (dofail)
			failmsg("netlink_send_ext: bad netlink ack type", "type=%d", hdr->nlmsg_type);
		debug("netlink_send_ext: short netlink ack: %d\n", hdr->nlmsg_type);
		return -1;
	}
	errno = -((struct nlmsgerr*)(hdr + 1))->error;
	return -errno;
}

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI || SYZ_WIFI || SYZ_802154 || \
    __NR_syz_80211_join_ibss || __NR_syz_80211_inject_frame
static int netlink_send(struct nlmsg* nlmsg, int sock)
{
	return netlink_send_ext(nlmsg, sock, 0, NULL, true);
}
#endif

static int netlink_query_family_id(struct nlmsg* nlmsg, int sock, const char* family_name, bool dofail)
{
	struct genlmsghdr genlhdr;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = CTRL_CMD_GETFAMILY;
	netlink_init(nlmsg, GENL_ID_CTRL, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, CTRL_ATTR_FAMILY_NAME, family_name, strnlen(family_name, GENL_NAMSIZ - 1) + 1);
	int n = 0;
	int err = netlink_send_ext(nlmsg, sock, GENL_ID_CTRL, &n, dofail);
	if (err < 0) {
		debug("netlink: failed to get family id for %.*s: %s\n", GENL_NAMSIZ, family_name, strerror(errno));
		return -1;
	}
	uint16 id = 0;
	struct nlattr* attr = (struct nlattr*)(nlmsg->buf + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(genlhdr)));
	for (; (char*)attr < nlmsg->buf + n; attr = (struct nlattr*)((char*)attr + NLMSG_ALIGN(attr->nla_len))) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
			id = *(uint16*)(attr + 1);
			break;
		}
	}
	if (!id) {
		debug("netlink: failed to parse family id for %.*s\n", GENL_NAMSIZ, family_name);
		errno = EINVAL;
		return -1;
	}
	recv(sock, nlmsg->buf, sizeof(nlmsg->buf), 0); // recv ack

	return id;
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

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_802154
static void netlink_add_device_impl(struct nlmsg* nlmsg, const char* type,
				    const char* name, bool up)
{
	struct ifinfomsg hdr;
	memset(&hdr, 0, sizeof(hdr));
	if (up)
		hdr.ifi_flags = hdr.ifi_change = IFF_UP;
	netlink_init(nlmsg, RTM_NEWLINK, NLM_F_EXCL | NLM_F_CREATE, &hdr, sizeof(hdr));
	if (name)
		netlink_attr(nlmsg, IFLA_IFNAME, name, strlen(name));
	netlink_nest(nlmsg, IFLA_LINKINFO);
	netlink_attr(nlmsg, IFLA_INFO_KIND, type, strlen(type));
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
static void netlink_add_device(struct nlmsg* nlmsg, int sock, const char* type,
			       const char* name)
{
	netlink_add_device_impl(nlmsg, type, name, false);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: adding device %s type %s: %s\n", name, type, strerror(errno));
	}
}

static void netlink_add_veth(struct nlmsg* nlmsg, int sock, const char* name,
			     const char* peer)
{
	netlink_add_device_impl(nlmsg, "veth", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_nest(nlmsg, VETH_INFO_PEER);
	nlmsg->pos += sizeof(struct ifinfomsg);
	netlink_attr(nlmsg, IFLA_IFNAME, peer, strlen(peer));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: adding device %s type veth peer %s: %s\n", name, peer, strerror(errno));
	}
}

static void netlink_add_xfrm(struct nlmsg* nlmsg, int sock, const char* name)
{
	netlink_add_device_impl(nlmsg, "xfrm", name, true);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	int if_id = 1;
	// This is IFLA_XFRM_IF_ID attr which is not present in older kernel headers.
	netlink_attr(nlmsg, 2, &if_id, sizeof(if_id));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: adding device %s type xfrm if_id %d: %s\n", name, if_id, strerror(errno));
	}
}

static void netlink_add_hsr(struct nlmsg* nlmsg, int sock, const char* name,
			    const char* slave1, const char* slave2)
{
	netlink_add_device_impl(nlmsg, "hsr", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	int ifindex1 = if_nametoindex(slave1);
	netlink_attr(nlmsg, IFLA_HSR_SLAVE1, &ifindex1, sizeof(ifindex1));
	int ifindex2 = if_nametoindex(slave2);
	netlink_attr(nlmsg, IFLA_HSR_SLAVE2, &ifindex2, sizeof(ifindex2));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: adding device %s type hsr slave1 %s slave2 %s: %s\n", name, slave1, slave2, strerror(errno));
	}
}

static void netlink_add_linked(struct nlmsg* nlmsg, int sock, const char* type, const char* name, const char* link)
{
	netlink_add_device_impl(nlmsg, type, name, false);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: adding device %s type %s link %s: %s\n", name, type, link, strerror(errno));
	}
}

static void netlink_add_vlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link, uint16 id, uint16 proto)
{
	netlink_add_device_impl(nlmsg, "vlan", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_attr(nlmsg, IFLA_VLAN_ID, &id, sizeof(id));
	netlink_attr(nlmsg, IFLA_VLAN_PROTOCOL, &proto, sizeof(proto));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: add %s type vlan link %s id %d: %s\n", name, link, id, strerror(errno));
	}
}

static void netlink_add_macvlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link)
{
	netlink_add_device_impl(nlmsg, "macvlan", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	uint32 mode = MACVLAN_MODE_BRIDGE;
	netlink_attr(nlmsg, IFLA_MACVLAN_MODE, &mode, sizeof(mode));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: add %s type macvlan link %s mode %d: %s\n", name, link, mode, strerror(errno));
	}
}

static void netlink_add_geneve(struct nlmsg* nlmsg, int sock, const char* name, uint32 vni, struct in_addr* addr4, struct in6_addr* addr6)
{
	netlink_add_device_impl(nlmsg, "geneve", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_attr(nlmsg, IFLA_GENEVE_ID, &vni, sizeof(vni));
	if (addr4)
		netlink_attr(nlmsg, IFLA_GENEVE_REMOTE, addr4, sizeof(*addr4));
	if (addr6)
		netlink_attr(nlmsg, IFLA_GENEVE_REMOTE6, addr6, sizeof(*addr6));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: add %s type geneve vni %u: %s\n", name, vni, strerror(errno));
	}
}

#define IFLA_IPVLAN_FLAGS 2
#define IPVLAN_MODE_L3S 2
#undef IPVLAN_F_VEPA
#define IPVLAN_F_VEPA 2

static void netlink_add_ipvlan(struct nlmsg* nlmsg, int sock, const char* name, const char* link, uint16 mode, uint16 flags)
{
	netlink_add_device_impl(nlmsg, "ipvlan", name, false);
	netlink_nest(nlmsg, IFLA_INFO_DATA);
	netlink_attr(nlmsg, IFLA_IPVLAN_MODE, &mode, sizeof(mode));
	netlink_attr(nlmsg, IFLA_IPVLAN_FLAGS, &flags, sizeof(flags));
	netlink_done(nlmsg);
	netlink_done(nlmsg);
	int ifindex = if_nametoindex(link);
	netlink_attr(nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("netlink: add %s type ipvlan link %s mode %d: %s\n", name, link, mode, strerror(errno));
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI || SYZ_802154
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
	if (err < 0) {
		debug("netlink: device %s up master %s: %s\n", name, master ? master : "NULL", strerror(errno));
	}
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
	if (err < 0) {
		debug("netlink: add addr %s dev %s: %s\n", addr, dev, strerror(errno));
	}
}

static void netlink_add_addr6(struct nlmsg* nlmsg, int sock,
			      const char* dev, const char* addr)
{
	struct in6_addr in6_addr;
	inet_pton(AF_INET6, addr, &in6_addr);
	int err = netlink_add_addr(nlmsg, sock, dev, &in6_addr, sizeof(in6_addr));
	if (err < 0) {
		debug("netlink: add addr %s dev %s: %s\n", addr, dev, strerror(errno));
	}
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
	if (err < 0) {
		debug("netlink: add neigh %s addr %d lladdr %d: %s\n", name, addrsize, macsize, strerror(errno));
	}
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_NET_DEVICES || SYZ_NET_INJECTION || SYZ_DEVLINK_PCI || SYZ_WIFI || SYZ_802154
static struct nlmsg nlmsg;
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
#if ENABLE_NAPI_FRAGS
static int tun_frags_enabled;
#ifndef IFF_NAPI_FRAGS
#define IFF_NAPI_FRAGS 0x0020
#endif
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
	const int kTunFd = 200;
	if (dup2(tunfd, kTunFd) < 0)
		fail("dup2(tunfd, kTunFd) failed");
	close(tunfd);
	tunfd = kTunFd;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, TUN_IFACE, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	// Note: SYZ_ENABLE_NAPI_FRAGS is never enabled. This is code is only for reference
	// in case we figure out how IFF_NAPI_FRAGS works. With IFF_NAPI_FRAGS packets
	// don't reach destinations and bail out in udp_gro_receive (see #1594).
	// Also IFF_NAPI_FRAGS does not work with sandbox_namespace (see comment there).
#if ENABLE_NAPI_FRAGS
	ifr.ifr_flags |= IFF_NAPI | IFF_NAPI_FRAGS;
#endif
	if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0) {
#if ENABLE_NAPI_FRAGS
		// IFF_NAPI_FRAGS requires root, so try without it.
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
		if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0)
#endif
			fail("tun: ioctl(TUNSETIFF) failed");
	}
#if ENABLE_NAPI_FRAGS
	// If IFF_NAPI_FRAGS is not supported it will be silently dropped,
	// so query the effective flags.
	if (ioctl(tunfd, TUNGETIFF, (void*)&ifr) < 0)
		fail("tun: ioctl(TUNGETIFF) failed");
	tun_frags_enabled = (ifr.ifr_flags & IFF_NAPI_FRAGS) != 0;
	debug("tun_frags_enabled=%d\n", tun_frags_enabled);
#endif

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
const int kInitNetNsFd = 201; // see kMaxFd
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

#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
static void netlink_devlink_netns_move(const char* bus_name, const char* dev_name, int netns_fd)
{
	struct genlmsghdr genlhdr;
	int sock;
	int id, err;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock == -1)
		fail("socket(AF_NETLINK) failed");

	id = netlink_query_family_id(&nlmsg, sock, DEVLINK_FAMILY_NAME, true);
	if (id == -1)
		goto error;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = DEVLINK_CMD_RELOAD;
	netlink_init(&nlmsg, id, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, DEVLINK_ATTR_BUS_NAME, bus_name, strlen(bus_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_DEV_NAME, dev_name, strlen(dev_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_NETNS_FD, &netns_fd, sizeof(netns_fd));
	err = netlink_send(&nlmsg, sock);
	if (err < 0) {
		debug("netlink: failed to move devlink instance %s/%s into network namespace: %s\n",
		      bus_name, dev_name, strerror(errno));
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
		fail("socket(AF_NETLINK) failed");

	int rtsock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rtsock == -1)
		fail("socket(AF_NETLINK) failed");

	id = netlink_query_family_id(&nlmsg, sock, DEVLINK_FAMILY_NAME, true);
	if (id == -1)
		goto error;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = DEVLINK_CMD_PORT_GET;
	netlink_init(&nlmsg, id, NLM_F_DUMP, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, DEVLINK_ATTR_BUS_NAME, bus_name, strlen(bus_name) + 1);
	netlink_attr(&nlmsg, DEVLINK_ATTR_DEV_NAME, dev_name, strlen(dev_name) + 1);

	err = netlink_send_ext(&nlmsg, sock, id, &total_len, true);
	if (err < 0) {
		debug("netlink: failed to get port get reply: %s\n", strerror(errno));
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

#if SYZ_EXECUTOR || SYZ_WIFI || __NR_syz_80211_inject_frame || __NR_syz_80211_join_ibss

#define WIFI_INITIAL_DEVICE_COUNT 2
#define WIFI_MAC_BASE                              \
	{                                          \
		0x08, 0x02, 0x11, 0x00, 0x00, 0x00 \
	}
#define WIFI_IBSS_BSSID                            \
	{                                          \
		0x50, 0x50, 0x50, 0x50, 0x50, 0x50 \
	}
#define WIFI_IBSS_SSID                             \
	{                                          \
		0x10, 0x10, 0x10, 0x10, 0x10, 0x10 \
	}
#define WIFI_DEFAULT_FREQUENCY 2412
#define WIFI_DEFAULT_SIGNAL 0
#define WIFI_DEFAULT_RX_RATE 1

// consts from drivers/net/wireless/mac80211_hwsim.h
#define HWSIM_CMD_REGISTER 1
#define HWSIM_CMD_FRAME 2
#define HWSIM_CMD_NEW_RADIO 4
#define HWSIM_ATTR_SUPPORT_P2P_DEVICE 14
#define HWSIM_ATTR_PERM_ADDR 22

#endif

#if SYZ_EXECUTOR || SYZ_WIFI || __NR_syz_80211_join_ibss
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/ioctl.h>

// From linux/if.h, but we cannot include the file as it conflicts with net/if.h
#define IF_OPER_UP 6

// IBSS parameters for nl80211_join_ibss
struct join_ibss_props {
	int wiphy_freq;
	bool wiphy_freq_fixed;
	uint8* mac;
	uint8* ssid;
	int ssid_len;
};

static int set_interface_state(const char* interface_name, int on)
{
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		debug("set_interface_state: failed to open socket, errno %d\n", errno);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, interface_name);
	int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		debug("set_interface_state: failed to execute SIOCGIFFLAGS, ret %d\n", ret);
		close(sock);
		return -1;
	}

	if (on)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
	close(sock);
	if (ret < 0) {
		debug("set_interface_state: failed to execute SIOCSIFFLAGS, ret %d\n", ret);
		return -1;
	}
	return 0;
}

static int nl80211_set_interface(struct nlmsg* nlmsg, int sock, int nl80211_family, uint32 ifindex, uint32 iftype)
{
	struct genlmsghdr genlhdr;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = NL80211_CMD_SET_INTERFACE;
	netlink_init(nlmsg, nl80211_family, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
	netlink_attr(nlmsg, NL80211_ATTR_IFTYPE, &iftype, sizeof(iftype));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("nl80211_set_interface failed: %s\n", strerror(errno));
	}
	return err;
}

static int nl80211_join_ibss(struct nlmsg* nlmsg, int sock, int nl80211_family, uint32 ifindex, struct join_ibss_props* props)
{
	struct genlmsghdr genlhdr;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = NL80211_CMD_JOIN_IBSS;
	netlink_init(nlmsg, nl80211_family, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
	netlink_attr(nlmsg, NL80211_ATTR_SSID, props->ssid, props->ssid_len);
	netlink_attr(nlmsg, NL80211_ATTR_WIPHY_FREQ, &(props->wiphy_freq), sizeof(props->wiphy_freq));
	if (props->mac)
		netlink_attr(nlmsg, NL80211_ATTR_MAC, props->mac, ETH_ALEN);
	if (props->wiphy_freq_fixed)
		netlink_attr(nlmsg, NL80211_ATTR_FREQ_FIXED, NULL, 0);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("nl80211_join_ibss failed: %s\n", strerror(errno));
	}
	return err;
}

static int get_ifla_operstate(struct nlmsg* nlmsg, int ifindex)
{
	struct ifinfomsg info;
	memset(&info, 0, sizeof(info));
	info.ifi_family = AF_UNSPEC;
	info.ifi_index = ifindex;

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1) {
		debug("get_ifla_operstate: socket failed: %d\n", errno);
		return -1;
	}

	netlink_init(nlmsg, RTM_GETLINK, 0, &info, sizeof(info));
	int n;
	int err = netlink_send_ext(nlmsg, sock, RTM_NEWLINK, &n, true);
	close(sock);

	if (err) {
		debug("get_ifla_operstate: failed to query: %s\n", strerror(errno));
		return -1;
	}

	struct rtattr* attr = IFLA_RTA(NLMSG_DATA(nlmsg->buf));
	for (; RTA_OK(attr, n); attr = RTA_NEXT(attr, n)) {
		if (attr->rta_type == IFLA_OPERSTATE)
			return *((int32_t*)RTA_DATA(attr));
	}

	return -1;
}

static int await_ifla_operstate(struct nlmsg* nlmsg, char* interface, int operstate)
{
	int ifindex = if_nametoindex(interface);
	while (true) {
		usleep(1000); // 1 ms
		int ret = get_ifla_operstate(nlmsg, ifindex);
		if (ret < 0)
			return ret;
		if (ret == operstate)
			return 0;
	}
	return 0;
}

static int nl80211_setup_ibss_interface(struct nlmsg* nlmsg, int sock, int nl80211_family_id, char* interface, struct join_ibss_props* ibss_props)
{
	int ifindex = if_nametoindex(interface);
	if (ifindex == 0) {
		debug("nl80211_setup_ibss_interface: if_nametoindex failed for %.32s, ret 0\n", interface);
		return -1;
	}

	int ret = nl80211_set_interface(nlmsg, sock, nl80211_family_id, ifindex, NL80211_IFTYPE_ADHOC);
	if (ret < 0) {
		debug("nl80211_setup_ibss_interface: nl80211_set_interface failed for %.32s, ret %d\n", interface, ret);
		return -1;
	}

	ret = set_interface_state(interface, 1);
	if (ret < 0) {
		debug("nl80211_setup_ibss_interface: set_interface_state failed for %.32s, ret %d\n", interface, ret);
		return -1;
	}

	ret = nl80211_join_ibss(nlmsg, sock, nl80211_family_id, ifindex, ibss_props);
	if (ret < 0) {
		debug("nl80211_setup_ibss_interface: nl80211_join_ibss failed for %.32s, ret %d\n", interface, ret);
		return -1;
	}

	return 0;
}
#endif

#if SYZ_EXECUTOR || SYZ_WIFI
#include <fcntl.h>
#include <linux/rfkill.h>
#include <sys/stat.h>
#include <sys/types.h>

static int hwsim80211_create_device(struct nlmsg* nlmsg, int sock, int hwsim_family, uint8 mac_addr[ETH_ALEN])
{
	struct genlmsghdr genlhdr;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = HWSIM_CMD_NEW_RADIO;
	netlink_init(nlmsg, hwsim_family, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, HWSIM_ATTR_SUPPORT_P2P_DEVICE, NULL, 0);
	netlink_attr(nlmsg, HWSIM_ATTR_PERM_ADDR, mac_addr, ETH_ALEN);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("hwsim80211_create_device failed: %s\n", strerror(errno));
	}
	return err;
}

static void initialize_wifi_devices(void)
{
	// Set up virtual wifi devices and join them into an IBSS network.
	// An IBSS network is created here in order to put these devices in an operable state right from
	// the beginning. It has the following positive effects.
	// 1. Frame injection becomes possible from the very start.
	// 2. A number of nl80211 commands expect their target wireless interface to be in an operable state.
	// 3. Simplification of reproducer generation - in many cases the reproducer will not have to spend time
	//    selecting system calls that set up the environment.
	//
	// IBSS network was chosen as the simplest network type to begin with.

#if SYZ_EXECUTOR
	if (!flag_wifi)
		return;
#endif
	int rfkill = open("/dev/rfkill", O_RDWR);
	if (rfkill == -1) {
		if (errno != ENOENT && errno != EACCES)
			fail("open(/dev/rfkill) failed");
	} else {
		struct rfkill_event event = {0};
		event.type = RFKILL_TYPE_ALL;
		event.op = RFKILL_OP_CHANGE_ALL;
		if (write(rfkill, &event, sizeof(event)) != (ssize_t)(sizeof(event)))
			fail("write(/dev/rfkill) failed");
		close(rfkill);
	}

	uint8 mac_addr[6] = WIFI_MAC_BASE;
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		debug("initialize_wifi_devices: failed to create socket (%d)\n", errno);
		return;
	}

	int hwsim_family_id = netlink_query_family_id(&nlmsg, sock, "MAC80211_HWSIM", true);
	int nl80211_family_id = netlink_query_family_id(&nlmsg, sock, "nl80211", true);
	uint8 ssid[] = WIFI_IBSS_SSID;
	uint8 bssid[] = WIFI_IBSS_BSSID;
	struct join_ibss_props ibss_props = {
	    .wiphy_freq = WIFI_DEFAULT_FREQUENCY, .wiphy_freq_fixed = true, .mac = bssid, .ssid = ssid, .ssid_len = sizeof(ssid)};

	for (int device_id = 0; device_id < WIFI_INITIAL_DEVICE_COUNT; device_id++) {
		// Virtual wifi devices will have consequtive mac addresses
		mac_addr[5] = device_id;
		int ret = hwsim80211_create_device(&nlmsg, sock, hwsim_family_id, mac_addr);
		if (ret < 0)
			failmsg("initialize_wifi_devices: failed to create device", "device=%d", device_id);

		// For each device, unless HWSIM_ATTR_NO_VIF is passed, a network interface is created
		// automatically. Such interfaces are named "wlan0", "wlan1" and so on.
		char interface[6] = "wlan0";
		interface[4] += device_id;

		if (nl80211_setup_ibss_interface(&nlmsg, sock, nl80211_family_id, interface, &ibss_props) < 0)
			failmsg("initialize_wifi_devices: failed set up IBSS network", "device=%d", device_id);
	}

	// Wait for all devices to join the IBSS network
	for (int device_id = 0; device_id < WIFI_INITIAL_DEVICE_COUNT; device_id++) {
		char interface[6] = "wlan0";
		interface[4] += device_id;
		int ret = await_ifla_operstate(&nlmsg, interface, IF_OPER_UP);
		if (ret < 0)
			failmsg("initialize_wifi_devices: get_ifla_operstate failed",
				"device=%d, ret=%d", device_id, ret);
	}

	close(sock);
}
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
	// These devices are sticky and are not deleted on net namespace destruction.
	// So try to delete the previous version of the device.
	write_file("/sys/bus/netdevsim/del_device", "%u", addr);
	if (write_file("/sys/bus/netdevsim/new_device", "%u %u", addr, port_count)) {
		char buf[32];
		snprintf(buf, sizeof(buf), "netdevsim%d", addr);
		initialize_devlink_ports("netdevsim", buf, "netdevsim");
	}
}

#define WG_GENL_NAME "wireguard"
enum wg_cmd {
	WG_CMD_GET_DEVICE,
	WG_CMD_SET_DEVICE,
};
enum wgdevice_attribute {
	WGDEVICE_A_UNSPEC,
	WGDEVICE_A_IFINDEX,
	WGDEVICE_A_IFNAME,
	WGDEVICE_A_PRIVATE_KEY,
	WGDEVICE_A_PUBLIC_KEY,
	WGDEVICE_A_FLAGS,
	WGDEVICE_A_LISTEN_PORT,
	WGDEVICE_A_FWMARK,
	WGDEVICE_A_PEERS,
};
enum wgpeer_attribute {
	WGPEER_A_UNSPEC,
	WGPEER_A_PUBLIC_KEY,
	WGPEER_A_PRESHARED_KEY,
	WGPEER_A_FLAGS,
	WGPEER_A_ENDPOINT,
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	WGPEER_A_LAST_HANDSHAKE_TIME,
	WGPEER_A_RX_BYTES,
	WGPEER_A_TX_BYTES,
	WGPEER_A_ALLOWEDIPS,
	WGPEER_A_PROTOCOL_VERSION,
};
enum wgallowedip_attribute {
	WGALLOWEDIP_A_UNSPEC,
	WGALLOWEDIP_A_FAMILY,
	WGALLOWEDIP_A_IPADDR,
	WGALLOWEDIP_A_CIDR_MASK,
};

static void netlink_wireguard_setup(void)
{
	const char ifname_a[] = "wg0";
	const char ifname_b[] = "wg1";
	const char ifname_c[] = "wg2";
	const char private_a[] = "\xa0\x5c\xa8\x4f\x6c\x9c\x8e\x38\x53\xe2\xfd\x7a\x70\xae\x0f\xb2\x0f\xa1\x52\x60\x0c\xb0\x08\x45\x17\x4f\x08\x07\x6f\x8d\x78\x43";
	const char private_b[] = "\xb0\x80\x73\xe8\xd4\x4e\x91\xe3\xda\x92\x2c\x22\x43\x82\x44\xbb\x88\x5c\x69\xe2\x69\xc8\xe9\xd8\x35\xb1\x14\x29\x3a\x4d\xdc\x6e";
	const char private_c[] = "\xa0\xcb\x87\x9a\x47\xf5\xbc\x64\x4c\x0e\x69\x3f\xa6\xd0\x31\xc7\x4a\x15\x53\xb6\xe9\x01\xb9\xff\x2f\x51\x8c\x78\x04\x2f\xb5\x42";
	const char public_a[] = "\x97\x5c\x9d\x81\xc9\x83\xc8\x20\x9e\xe7\x81\x25\x4b\x89\x9f\x8e\xd9\x25\xae\x9f\x09\x23\xc2\x3c\x62\xf5\x3c\x57\xcd\xbf\x69\x1c";
	const char public_b[] = "\xd1\x73\x28\x99\xf6\x11\xcd\x89\x94\x03\x4d\x7f\x41\x3d\xc9\x57\x63\x0e\x54\x93\xc2\x85\xac\xa4\x00\x65\xcb\x63\x11\xbe\x69\x6b";
	const char public_c[] = "\xf4\x4d\xa3\x67\xa8\x8e\xe6\x56\x4f\x02\x02\x11\x45\x67\x27\x08\x2f\x5c\xeb\xee\x8b\x1b\xf5\xeb\x73\x37\x34\x1b\x45\x9b\x39\x22";
	const uint16 listen_a = 20001;
	const uint16 listen_b = 20002;
	const uint16 listen_c = 20003;
	const uint16 af_inet = AF_INET;
	const uint16 af_inet6 = AF_INET6;
	// Unused, but useful in case we change this:
	// const struct sockaddr_in endpoint_a_v4 = {
	//     .sin_family = AF_INET,
	//     .sin_port = htons(listen_a),
	//     .sin_addr = {htonl(INADDR_LOOPBACK)}};
	const struct sockaddr_in endpoint_b_v4 = {
	    .sin_family = AF_INET,
	    .sin_port = htons(listen_b),
	    .sin_addr = {htonl(INADDR_LOOPBACK)}};
	const struct sockaddr_in endpoint_c_v4 = {
	    .sin_family = AF_INET,
	    .sin_port = htons(listen_c),
	    .sin_addr = {htonl(INADDR_LOOPBACK)}};
	struct sockaddr_in6 endpoint_a_v6 = {
	    .sin6_family = AF_INET6,
	    .sin6_port = htons(listen_a)};
	endpoint_a_v6.sin6_addr = in6addr_loopback;
	// Unused, but useful in case we change this:
	// const struct sockaddr_in6 endpoint_b_v6 = {
	//     .sin6_family = AF_INET6,
	//     .sin6_port = htons(listen_b)};
	// endpoint_b_v6.sin6_addr = in6addr_loopback;
	struct sockaddr_in6 endpoint_c_v6 = {
	    .sin6_family = AF_INET6,
	    .sin6_port = htons(listen_c)};
	endpoint_c_v6.sin6_addr = in6addr_loopback;
	const struct in_addr first_half_v4 = {0};
	const struct in_addr second_half_v4 = {(uint32)htonl(128 << 24)};
	const struct in6_addr first_half_v6 = {{{0}}};
	const struct in6_addr second_half_v6 = {{{0x80}}};
	const uint8 half_cidr = 1;
	const uint16 persistent_keepalives[] = {1, 3, 7, 9, 14, 19};

	struct genlmsghdr genlhdr = {
	    .cmd = WG_CMD_SET_DEVICE,
	    .version = 1};
	int sock;
	int id, err;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock == -1) {
		debug("socket(AF_NETLINK) failed: %s\n", strerror(errno));
		return;
	}

	id = netlink_query_family_id(&nlmsg, sock, WG_GENL_NAME, true);
	if (id == -1)
		goto error;

	netlink_init(&nlmsg, id, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, WGDEVICE_A_IFNAME, ifname_a, strlen(ifname_a) + 1);
	netlink_attr(&nlmsg, WGDEVICE_A_PRIVATE_KEY, private_a, 32);
	netlink_attr(&nlmsg, WGDEVICE_A_LISTEN_PORT, &listen_a, 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGDEVICE_A_PEERS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_b, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_b_v4, sizeof(endpoint_b_v4));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[0], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v4, sizeof(first_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v6, sizeof(first_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_c, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_c_v6, sizeof(endpoint_c_v6));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[1], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v4, sizeof(second_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v6, sizeof(second_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	err = netlink_send(&nlmsg, sock);
	if (err < 0) {
		debug("netlink: failed to setup wireguard instance: %s\n", strerror(errno));
	}

	netlink_init(&nlmsg, id, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, WGDEVICE_A_IFNAME, ifname_b, strlen(ifname_b) + 1);
	netlink_attr(&nlmsg, WGDEVICE_A_PRIVATE_KEY, private_b, 32);
	netlink_attr(&nlmsg, WGDEVICE_A_LISTEN_PORT, &listen_b, 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGDEVICE_A_PEERS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_a, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_a_v6, sizeof(endpoint_a_v6));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[2], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v4, sizeof(first_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v6, sizeof(first_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_c, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_c_v4, sizeof(endpoint_c_v4));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[3], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v4, sizeof(second_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v6, sizeof(second_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	err = netlink_send(&nlmsg, sock);
	if (err < 0) {
		debug("netlink: failed to setup wireguard instance: %s\n", strerror(errno));
	}

	netlink_init(&nlmsg, id, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(&nlmsg, WGDEVICE_A_IFNAME, ifname_c, strlen(ifname_c) + 1);
	netlink_attr(&nlmsg, WGDEVICE_A_PRIVATE_KEY, private_c, 32);
	netlink_attr(&nlmsg, WGDEVICE_A_LISTEN_PORT, &listen_c, 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGDEVICE_A_PEERS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_a, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_a_v6, sizeof(endpoint_a_v6));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[4], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v4, sizeof(first_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &first_half_v6, sizeof(first_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGPEER_A_PUBLIC_KEY, public_b, 32);
	netlink_attr(&nlmsg, WGPEER_A_ENDPOINT, &endpoint_b_v4, sizeof(endpoint_b_v4));
	netlink_attr(&nlmsg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, &persistent_keepalives[5], 2);
	netlink_nest(&nlmsg, NLA_F_NESTED | WGPEER_A_ALLOWEDIPS);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v4, sizeof(second_half_v4));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_nest(&nlmsg, NLA_F_NESTED | 0);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_FAMILY, &af_inet6, 2);
	netlink_attr(&nlmsg, WGALLOWEDIP_A_IPADDR, &second_half_v6, sizeof(second_half_v6));
	netlink_attr(&nlmsg, WGALLOWEDIP_A_CIDR_MASK, &half_cidr, 1);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	netlink_done(&nlmsg);
	err = netlink_send(&nlmsg, sock);
	if (err < 0) {
		debug("netlink: failed to setup wireguard instance: %s\n", strerror(errno));
	}

error:
	close(sock);
}

#if SYZ_EXECUTOR || SYZ_NIC_VF
static int runcmdline(char* cmdline)
{
	debug("%s\n", cmdline);
	int ret = system(cmdline);
	if (ret) {
		debug("FAIL: %s\n", cmdline);
	}
	return ret;
}

static void netlink_nicvf_setup(void)
{
	char cmdline[256];

#if SYZ_EXECUTOR
	if (!flag_nic_vf)
		return;
#endif
	if (!vf_intf.ppid)
		return;

	debug("ppid = %d, vf_intf.pass_thru_intf: %s\n",
	      vf_intf.ppid, vf_intf.pass_thru_intf);

	sprintf(cmdline, "nsenter -t 1 -n ip link set %s netns %d",
		vf_intf.pass_thru_intf, getpid());
	if (runcmdline(cmdline))
		return;

	sprintf(cmdline, "ip a s %s", vf_intf.pass_thru_intf);
	if (runcmdline(cmdline))
		return;

	sprintf(cmdline, "ip link set %s down", vf_intf.pass_thru_intf);
	if (runcmdline(cmdline))
		return;

	sprintf(cmdline, "ip link set %s name nicvf0", vf_intf.pass_thru_intf);
	if (runcmdline(cmdline))
		return;

	debug("nicvf0 VF pass-through setup complete.\n");
}
#endif // SYZ_NIC_VF

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
	// - ipip
	// - lowpan (requires link to device of type IEEE802154, e.g. wpan0)
	// - ipoib (requires link to device of type ARPHRD_INFINIBAND)
	// - vrf
	// - rmnet
	// - openvswitch
	// Naive attempts to add devices of these types fail with various errors.
	// Also init namespace contains the following devices (which presumably can't be
	// created in non-init namespace), can we use them somehow?
	// - ifb0/1
	// - teql0
	// - eql
	// Note: netdevsim devices can't have the same name even in different namespaces.
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
#if SYZ_EXECUTOR || SYZ_NIC_VF
		{"nicvf", "nicvf0"},
#endif
		{"nlmon", "nlmon0"},
		{"caif", "caif0"},
		{"batadv", "batadv0"},
		// Note: this adds vxcan0/vxcan1 pair, similar to veth (creating vxcan0 would fail).
		{"vxcan", "vxcan1"},
		// This adds connected veth0 and veth1 devices.
		{"veth", 0},
		{"wireguard", "wg0"},
		{"wireguard", "wg1"},
		{"wireguard", "wg2"},
	};
	const char* devmasters[] = {"bridge", "bond", "team", "batadv"};
	// If you extend this array, also update netdev_addr_id in vnet.txt
	// and devnames in socket.txt.
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
#if SYZ_EXECUTOR || SYZ_NIC_VF
		{"nicvf0", 0, true},
#endif
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
		{"veth0_macvtap", ETH_ALEN},
		{"veth1_macvtap", ETH_ALEN},
		{"macvtap0", ETH_ALEN},
		{"macsec0", ETH_ALEN},
		{"veth0_to_batadv", ETH_ALEN},
		{"veth1_to_batadv", ETH_ALEN},
		{"batadv_slave_0", ETH_ALEN},
		{"batadv_slave_1", ETH_ALEN},
		{"geneve0", ETH_ALEN},
		{"geneve1", ETH_ALEN},
		{"wg0", 0},
		{"wg1", 0},
		{"wg2", 0},
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
	netlink_add_xfrm(&nlmsg, sock, "xfrm0");

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
	netlink_add_linked(&nlmsg, sock, "virt_wifi", "virt_wifi0", "veth1_virt_wifi");

	netlink_add_veth(&nlmsg, sock, "veth0_vlan", "veth1_vlan");
	netlink_add_vlan(&nlmsg, sock, "vlan0", "veth0_vlan", 0, htons(ETH_P_8021Q));
	netlink_add_vlan(&nlmsg, sock, "vlan1", "veth0_vlan", 1, htons(ETH_P_8021AD));
	netlink_add_macvlan(&nlmsg, sock, "macvlan0", "veth1_vlan");
	netlink_add_macvlan(&nlmsg, sock, "macvlan1", "veth1_vlan");
	netlink_add_ipvlan(&nlmsg, sock, "ipvlan0", "veth0_vlan", IPVLAN_MODE_L2, 0);
	netlink_add_ipvlan(&nlmsg, sock, "ipvlan1", "veth0_vlan", IPVLAN_MODE_L3S, IPVLAN_F_VEPA);

	netlink_add_veth(&nlmsg, sock, "veth0_macvtap", "veth1_macvtap");
	netlink_add_linked(&nlmsg, sock, "macvtap", "macvtap0", "veth0_macvtap");
	netlink_add_linked(&nlmsg, sock, "macsec", "macsec0", "veth1_macvtap");

	char addr[32];
	sprintf(addr, DEV_IPV4, 14 + 10); // should point to veth0
	struct in_addr geneve_addr4;
	if (inet_pton(AF_INET, addr, &geneve_addr4) <= 0)
		fail("geneve0 inet_pton failed");
	struct in6_addr geneve_addr6;
	// Must not be link local (our device addresses are link local).
	if (inet_pton(AF_INET6, "fc00::01", &geneve_addr6) <= 0)
		fail("geneve1 inet_pton failed");
	netlink_add_geneve(&nlmsg, sock, "geneve0", 0, &geneve_addr4, 0);
	netlink_add_geneve(&nlmsg, sock, "geneve1", 1, 0, &geneve_addr6);

	netdevsim_add((int)procid, 4); // Number of port is in sync with value in sys/linux/socket_netlink_generic_devlink.txt

	netlink_wireguard_setup();

#if SYZ_EXECUTOR || SYZ_NIC_VF
	netlink_nicvf_setup();
#endif

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

#if SYZ_EXECUTOR || SYZ_NIC_VF
	find_vf_interface();
#endif
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
		// Tun sometimes returns EBADFD, unclear if it's a kernel bug or not.
		if (errno == EAGAIN || errno == EBADFD)
			return -1;
		fail("tun read failed");
	}
	return rv;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet && SYZ_NET_INJECTION
#include <stdbool.h>
#include <sys/uio.h>

#if ENABLE_NAPI_FRAGS
#define MAX_FRAGS 4
struct vnet_fragmentation {
	uint32 full;
	uint32 count;
	uint32 frags[MAX_FRAGS];
};
#endif

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

#if ENABLE_NAPI_FRAGS
	struct vnet_fragmentation* frags = (struct vnet_fragmentation*)a2;
	struct iovec vecs[MAX_FRAGS + 1];
	uint32 nfrags = 0;
	if (!tun_frags_enabled || frags == NULL) {
		vecs[nfrags].iov_base = data;
		vecs[nfrags].iov_len = length;
		nfrags++;
	} else {
		bool full = frags->full;
		uint32 count = frags->count;
		if (count > MAX_FRAGS)
			count = MAX_FRAGS;
		uint32 i;
		for (i = 0; i < count && length != 0; i++) {
			uint32 size = frags->frags[i];
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
#else
	return write(tunfd, data, length);
#endif
}
#endif

#if SYZ_EXECUTOR || __NR_syz_io_uring_submit || __NR_syz_io_uring_complete || __NR_syz_io_uring_setup

#define SIZEOF_IO_URING_SQE 64
#define SIZEOF_IO_URING_CQE 16

// Once a io_uring is set up by calling io_uring_setup, the offsets to the member fields
// to be used on the mmap'ed area are set in structs io_sqring_offsets and io_cqring_offsets.
// Except io_sqring_offsets.array, the offsets are static while all depend on how struct io_rings
// is organized in code. The offsets can be marked as resources in syzkaller descriptions but
// this makes it difficult to generate correct programs by the fuzzer. Thus, the offsets are
// hard-coded here (and in the descriptions), and array offset is later computed once the number
// of entries is available. Another way to obtain the offsets is to setup another io_uring here
// and use what it returns. It is slower but might be more maintainable.
#define SQ_HEAD_OFFSET 0
#define SQ_TAIL_OFFSET 64
#define SQ_RING_MASK_OFFSET 256
#define SQ_RING_ENTRIES_OFFSET 264
#define SQ_FLAGS_OFFSET 276
#define SQ_DROPPED_OFFSET 272
#define CQ_HEAD_OFFSET 128
#define CQ_TAIL_OFFSET 192
#define CQ_RING_MASK_OFFSET 260
#define CQ_RING_ENTRIES_OFFSET 268
#define CQ_RING_OVERFLOW_OFFSET 284
#define CQ_FLAGS_OFFSET 280
#define CQ_CQES_OFFSET 320

#if SYZ_EXECUTOR || __NR_syz_io_uring_complete

// From linux/io_uring.h
struct io_uring_cqe {
	uint64 user_data;
	uint32 res;
	uint32 flags;
};

static long syz_io_uring_complete(volatile long a0)
{
	// syzlang: syz_io_uring_complete(ring_ptr ring_ptr)
	// C:       syz_io_uring_complete(char* ring_ptr)

	// It is not checked if the ring is empty

	// Cast to original
	char* ring_ptr = (char*)a0;

	// Compute the head index and the next head value
	uint32 cq_ring_mask = *(uint32*)(ring_ptr + CQ_RING_MASK_OFFSET);
	uint32* cq_head_ptr = (uint32*)(ring_ptr + CQ_HEAD_OFFSET);
	uint32 cq_head = *cq_head_ptr & cq_ring_mask;
	uint32 cq_head_next = *cq_head_ptr + 1;

	// Compute the ptr to the src cq entry on the ring
	char* cqe_src = ring_ptr + CQ_CQES_OFFSET + cq_head * SIZEOF_IO_URING_CQE;

	// Get the cq entry from the ring
	struct io_uring_cqe cqe;
	memcpy(&cqe, cqe_src, sizeof(cqe));

	// Advance the head. Head is a free-flowing integer and relies on natural wrapping.
	// Ensure that the kernel will never see a head update without the preceeding CQE
	// stores being done.
	__atomic_store_n(cq_head_ptr, cq_head_next, __ATOMIC_RELEASE);

	// In the descriptions (sys/linux/io_uring.txt), openat and openat2 are passed
	// with a unique range of sqe.user_data (0x12345 and 0x23456) to identify the operations
	// which produces an fd instance. Check cqe.user_data, which should be the same
	// as sqe.user_data for that operation. If it falls in that unique range, return
	// cqe.res as fd. Otherwise, just return an invalid fd.
	return (cqe.user_data == 0x12345 || cqe.user_data == 0x23456) ? (long)cqe.res : (long)-1;
}

#endif

#if SYZ_EXECUTOR || __NR_syz_io_uring_setup

struct io_sqring_offsets {
	uint32 head;
	uint32 tail;
	uint32 ring_mask;
	uint32 ring_entries;
	uint32 flags;
	uint32 dropped;
	uint32 array;
	uint32 resv1;
	uint64 resv2;
};

struct io_cqring_offsets {
	uint32 head;
	uint32 tail;
	uint32 ring_mask;
	uint32 ring_entries;
	uint32 overflow;
	uint32 cqes;
	uint64 resv[2];
};

struct io_uring_params {
	uint32 sq_entries;
	uint32 cq_entries;
	uint32 flags;
	uint32 sq_thread_cpu;
	uint32 sq_thread_idle;
	uint32 features;
	uint32 resv[4];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

#define IORING_OFF_SQ_RING 0
#define IORING_OFF_SQES 0x10000000ULL

#include <sys/mman.h>
#include <unistd.h>

// Wrapper for io_uring_setup and the subsequent mmap calls that map the ring and the sqes
static long syz_io_uring_setup(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5)
{
	// syzlang: syz_io_uring_setup(entries int32[1:IORING_MAX_ENTRIES], params ptr[inout, io_uring_params], addr_ring vma, addr_sqes vma, ring_ptr ptr[out, ring_ptr], sqes_ptr ptr[out, sqes_ptr]) fd_io_uring
	// C:       syz_io_uring_setup(uint32 entries, struct io_uring_params* params, void* mmap_addr_ring, void* mmap_addr_sqes, void** ring_ptr_out, void** sqes_ptr_out) // returns uint32 fd_io_uring

	// Cast to original
	uint32 entries = (uint32)a0;
	struct io_uring_params* setup_params = (struct io_uring_params*)a1;
	void* vma1 = (void*)a2;
	void* vma2 = (void*)a3;
	void** ring_ptr_out = (void**)a4;
	void** sqes_ptr_out = (void**)a5;

	uint32 fd_io_uring = syscall(__NR_io_uring_setup, entries, setup_params);

	// Compute the ring sizes
	uint32 sq_ring_sz = setup_params->sq_off.array + setup_params->sq_entries * sizeof(uint32);
	uint32 cq_ring_sz = setup_params->cq_off.cqes + setup_params->cq_entries * SIZEOF_IO_URING_CQE;

	// Asssumed IORING_FEAT_SINGLE_MMAP, which is always the case with the current implementation
	// The implication is that the sq_ring_ptr and the cq_ring_ptr are the same but the
	// difference is in the offsets to access the fields of these rings.
	uint32 ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;
	*ring_ptr_out = mmap(vma1, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd_io_uring, IORING_OFF_SQ_RING);

	uint32 sqes_sz = setup_params->sq_entries * SIZEOF_IO_URING_SQE;
	*sqes_ptr_out = mmap(vma2, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd_io_uring, IORING_OFF_SQES);

	return fd_io_uring;
}

#endif

#if SYZ_EXECUTOR || __NR_syz_io_uring_submit

static long syz_io_uring_submit(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	// syzlang: syz_io_uring_submit(ring_ptr ring_ptr, sqes_ptr sqes_ptr, 		sqe ptr[in, io_uring_sqe],   sqes_index int32)
	// C:       syz_io_uring_submit(char* ring_ptr,       io_uring_sqe* sqes_ptr,    io_uring_sqe* sqe,           uint32 sqes_index)

	// It is not checked if the ring is full

	// Cast to original
	char* ring_ptr = (char*)a0; // This will be exposed to offsets in bytes
	char* sqes_ptr = (char*)a1;
	char* sqe = (char*)a2;
	uint32 sqes_index = (uint32)a3;

	uint32 sq_ring_entries = *(uint32*)(ring_ptr + SQ_RING_ENTRIES_OFFSET);
	uint32 cq_ring_entries = *(uint32*)(ring_ptr + CQ_RING_ENTRIES_OFFSET);

	// Compute the sq_array offset
	uint32 sq_array_off = (CQ_CQES_OFFSET + cq_ring_entries * SIZEOF_IO_URING_CQE + 63) & ~63;

	// Get the ptr to the destination for the sqe
	if (sq_ring_entries)
		sqes_index %= sq_ring_entries;
	char* sqe_dest = sqes_ptr + sqes_index * SIZEOF_IO_URING_SQE;

	// Write the sqe entry to its destination in sqes
	memcpy(sqe_dest, sqe, SIZEOF_IO_URING_SQE);

	// Write the index to the sqe array
	uint32 sq_ring_mask = *(uint32*)(ring_ptr + SQ_RING_MASK_OFFSET);
	uint32* sq_tail_ptr = (uint32*)(ring_ptr + SQ_TAIL_OFFSET);
	uint32 sq_tail = *sq_tail_ptr & sq_ring_mask;
	uint32 sq_tail_next = *sq_tail_ptr + 1;
	uint32* sq_array = (uint32*)(ring_ptr + sq_array_off);
	*(sq_array + sq_tail) = sqes_index;

	// Advance the tail. Tail is a free-flowing integer and relies on natural wrapping.
	// Ensure that the kernel will never see a tail update without the preceeding SQE
	// stores being done.
	__atomic_store_n(sq_tail_ptr, sq_tail_next, __ATOMIC_RELEASE);

	// Now the application is free to call io_uring_enter() to submit the sqe
	return 0;
}

#endif

#endif

#if SYZ_EXECUTOR || __NR_syz_usbip_server_init

#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// This should be coherent with CONFIG_USBIP_VHCI_HC_PORTS.
#define VHCI_HC_PORTS 8
#define VHCI_PORTS (VHCI_HC_PORTS * 2)

static long syz_usbip_server_init(volatile long a0)
{
	// port_alloc[0] corresponds to ports which can be used by usb2 and
	// port_alloc[1] corresponds to ports which can be used by usb3.
	static int port_alloc[2];

	int speed = (int)a0;
	bool usb3 = (speed == USB_SPEED_SUPER);

	int socket_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair))
		fail("syz_usbip_server_init: socketpair failed");

	int client_fd = socket_pair[0];
	int server_fd = socket_pair[1];

	int available_port_num = __atomic_fetch_add(&port_alloc[usb3], 1, __ATOMIC_RELAXED);
	if (available_port_num > VHCI_HC_PORTS) {
		debug("syz_usbip_server_init : no more available port for : %d\n", available_port_num);
		return -1;
	}

	// Each port number corresponds to a particular vhci_hcd (USB/IP Virtual Host Controller) and it is used by either
	// an usb2 device or usb3 device. There are 16 ports available in each vhci_hcd.
	// (VHCI_PORTS = 16 in our case.) When they are occupied, the following vhci_hcd's ports are used.
	// First 16 ports correspond to vhci_hcd0, next 16 ports correspond to
	// vhci_hcd1 etc. In a vhci_hcd, first 8 ports are used by usb2 devices and last 8 are used by usb3 devices.
	int port_num = procid * VHCI_PORTS + usb3 * VHCI_HC_PORTS + available_port_num;

	// Under normal USB/IP usage, devid represents the device ID on the server.
	// When fuzzing with syzkaller we don't have an actual server or an actual device, so use 0 for devid.
	char buffer[100];
	sprintf(buffer, "%d %d %s %d", port_num, client_fd, "0", speed);

	write_file("/sys/devices/platform/vhci_hcd.0/attach", buffer);
	return server_fd;
}

#endif

#if SYZ_EXECUTOR || __NR_syz_btf_id_by_name

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Some items in linux/btf.h are relatively new, so we copy them here for
// backward compatibility.
#define BTF_MAGIC 0xeB9F

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

#define BTF_INFO_KIND(info) (((info) >> 24) & 0x0f)
#define BTF_INFO_VLEN(info) ((info)&0xffff)

#define BTF_KIND_INT 1
#define BTF_KIND_ARRAY 3
#define BTF_KIND_STRUCT 4
#define BTF_KIND_UNION 5
#define BTF_KIND_ENUM 6
#define BTF_KIND_FUNC_PROTO 13
#define BTF_KIND_VAR 14
#define BTF_KIND_DATASEC 15

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

struct btf_enum {
	__u32 name_off;
	__s32 val;
};

struct btf_array {
	__u32 type;
	__u32 index_type;
	__u32 nelems;
};

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct btf_param {
	__u32 name_off;
	__u32 type;
};

struct btf_var {
	__u32 linkage;
};

struct btf_var_secinfo {
	__u32 type;
	__u32 offset;
	__u32 size;
};

// Set the limit on the maximum size of btf/vmlinux to be 10 MiB.
#define VMLINUX_MAX_SUPPORT_SIZE (10 * 1024 * 1024)

// Read out all the content of /sys/kernel/btf/vmlinux to the fixed address
// buffer and return it. Return NULL if failed.
static char* read_btf_vmlinux()
{
	static bool is_read = false;
	static char buf[VMLINUX_MAX_SUPPORT_SIZE];

	// There could be a race condition here, but it should not be harmful.
	if (is_read)
		return buf;

	int fd = open("/sys/kernel/btf/vmlinux", O_RDONLY);
	if (fd < 0)
		return NULL;

	unsigned long bytes_read = 0;
	for (;;) {
		ssize_t ret = read(fd, buf + bytes_read,
				   VMLINUX_MAX_SUPPORT_SIZE - bytes_read);

		if (ret < 0 || bytes_read + ret == VMLINUX_MAX_SUPPORT_SIZE)
			return NULL;

		if (ret == 0)
			break;

		bytes_read += ret;
	}

	is_read = true;
	return buf;
}

// Given a pointer to a C-string as the only argument a0, return the
// corresponding btf ID for this name. Return -1 if there is an error when
// opening the vmlinux file or the name is not found in vmlinux.
static long syz_btf_id_by_name(volatile long a0)
{
	// syzlang: syz_btf_id_by_name(name ptr[in, string]) btf_id
	// C:		syz_btf_id_by_name(char* name)
	char* target = (char*)a0;

	char* vmlinux = read_btf_vmlinux();
	if (vmlinux == NULL)
		return -1;

	struct btf_header* btf_header = (struct btf_header*)vmlinux;
	if (btf_header->magic != BTF_MAGIC)
		return -1;
	// These offsets are bytes relative to the end of the header.
	char* btf_type_sec = vmlinux + btf_header->hdr_len + btf_header->type_off;
	char* btf_str_sec = vmlinux + btf_header->hdr_len + btf_header->str_off;
	// Scan through the btf type section, and find a type description that
	// matches the provided name.
	unsigned int bytes_parsed = 0;
	// BTF index starts at 1.
	long idx = 1;
	while (bytes_parsed < btf_header->type_len) {
		struct btf_type* btf_type = (struct btf_type*)(btf_type_sec + bytes_parsed);
		uint32 kind = BTF_INFO_KIND(btf_type->info);
		uint32 vlen = BTF_INFO_VLEN(btf_type->info);
		char* name = btf_str_sec + btf_type->name_off;

		if (strcmp(name, target) == 0)
			return idx;

		// From /include/uapi/linux/btf.h, some kinds of types are
		// followed by extra data.
		size_t skip;
		switch (kind) {
		case BTF_KIND_INT:
			skip = sizeof(uint32);
			break;
		case BTF_KIND_ENUM:
			skip = sizeof(struct btf_enum) * vlen;
			break;
		case BTF_KIND_ARRAY:
			skip = sizeof(struct btf_array);
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			skip = sizeof(struct btf_member) * vlen;
			break;
		case BTF_KIND_FUNC_PROTO:
			skip = sizeof(struct btf_param) * vlen;
			break;
		case BTF_KIND_VAR:
			skip = sizeof(struct btf_var);
			break;
		case BTF_KIND_DATASEC:
			skip = sizeof(struct btf_var_secinfo) * vlen;
			break;
		default:
			skip = 0;
		}

		bytes_parsed += sizeof(struct btf_type) + skip;
		idx++;
	}

	return -1;
}

#endif // SYZ_EXECUTOR || __NR_syz_btf_id_by_name

// Same as memcpy except that it accepts offset to dest and src.
#if SYZ_EXECUTOR || __NR_syz_memcpy_off
static long syz_memcpy_off(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4)
{
	// C:       syz_memcpy_off(void* dest, uint32 dest_off, void* src, uint32 src_off, size_t n)

	// Cast to original
	char* dest = (char*)a0;
	uint32 dest_off = (uint32)a1;
	char* src = (char*)a2;
	uint32 src_off = (uint32)a3;
	size_t n = (size_t)a4;

	return (long)memcpy(dest + dest_off, src + src_off, n);
}
#endif

#if (SYZ_EXECUTOR || SYZ_REPEAT && SYZ_NET_INJECTION) && SYZ_EXECUTOR_USES_FORK_SERVER
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

	if (length < sizeof(struct ethhdr))
		return (uintptr_t)-1;
	struct ethhdr* ethhdr = (struct ethhdr*)&data[0];

	struct tcphdr* tcphdr = 0;
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
	res->seq = htonl((ntohl(tcphdr->seq) + (uint32)a1));
	res->ack = htonl((ntohl(tcphdr->ack_seq) + (uint32)a2));

	debug("extracted seq: %08x\n", res->seq);
	debug("extracted ack: %08x\n", res->ack);

	return 0;
}
#endif

#if SYZ_EXECUTOR || SYZ_CLOSE_FDS || __NR_syz_usb_connect || __NR_syz_usb_connect_ath9k
#define MAX_FDS 30
#endif

#if SYZ_EXECUTOR || __NR_syz_usb_connect || __NR_syz_usb_connect_ath9k
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

#include "common_usb_linux.h"
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
		strncpy(buf, (char*)a0, sizeof(buf) - 1);
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
		snprintf(buf, sizeof(buf), "/proc/self/%s", (char*)a1);
	} else if (a0 == -1) {
		snprintf(buf, sizeof(buf), "/proc/thread-self/%s", (char*)a1);
	} else {
		snprintf(buf, sizeof(buf), "/proc/self/task/%d/%s", (int)a0, (char*)a1);
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

#if SYZ_EXECUTOR || SYZ_VHCI_INJECTION
#include <errno.h>
#include <fcntl.h>
#include <linux/rfkill.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define BTPROTO_HCI 1
#define ACL_LINK 1
#define SCAN_PAGE 2

typedef struct {
	uint8 b[6];
} __attribute__((packed)) bdaddr_t;

#define HCI_COMMAND_PKT 1
#define HCI_EVENT_PKT 4
#define HCI_VENDOR_PKT 0xff

struct hci_command_hdr {
	uint16 opcode;
	uint8 plen;
} __attribute__((packed));

struct hci_event_hdr {
	uint8 evt;
	uint8 plen;
} __attribute__((packed));

#define HCI_EV_CONN_COMPLETE 0x03
struct hci_ev_conn_complete {
	uint8 status;
	uint16 handle;
	bdaddr_t bdaddr;
	uint8 link_type;
	uint8 encr_mode;
} __attribute__((packed));

#define HCI_EV_CONN_REQUEST 0x04
struct hci_ev_conn_request {
	bdaddr_t bdaddr;
	uint8 dev_class[3];
	uint8 link_type;
} __attribute__((packed));

#define HCI_EV_REMOTE_FEATURES 0x0b
struct hci_ev_remote_features {
	uint8 status;
	uint16 handle;
	uint8 features[8];
} __attribute__((packed));

#define HCI_EV_CMD_COMPLETE 0x0e
struct hci_ev_cmd_complete {
	uint8 ncmd;
	uint16 opcode;
} __attribute__((packed));

#define HCI_OP_WRITE_SCAN_ENABLE 0x0c1a

#define HCI_OP_READ_BUFFER_SIZE 0x1005
struct hci_rp_read_buffer_size {
	uint8 status;
	uint16 acl_mtu;
	uint8 sco_mtu;
	uint16 acl_max_pkt;
	uint16 sco_max_pkt;
} __attribute__((packed));

#define HCI_OP_READ_BD_ADDR 0x1009
struct hci_rp_read_bd_addr {
	uint8 status;
	bdaddr_t bdaddr;
} __attribute__((packed));

#define HCI_EV_LE_META 0x3e
struct hci_ev_le_meta {
	uint8 subevent;
} __attribute__((packed));

#define HCI_EV_LE_CONN_COMPLETE 0x01
struct hci_ev_le_conn_complete {
	uint8 status;
	uint16 handle;
	uint8 role;
	uint8 bdaddr_type;
	bdaddr_t bdaddr;
	uint16 interval;
	uint16 latency;
	uint16 supervision_timeout;
	uint8 clk_accurancy;
} __attribute__((packed));

struct hci_dev_req {
	uint16 dev_id;
	uint32 dev_opt;
};

struct vhci_vendor_pkt_request {
	uint8 type;
	uint8 opcode;
} __attribute__((packed));

struct vhci_pkt {
	uint8 type;
	union {
		struct {
			uint8 opcode;
			uint16 id;
		} __attribute__((packed)) vendor_pkt;
		struct hci_command_hdr command_hdr;
	};
} __attribute__((packed));

#define HCIDEVUP _IOW('H', 201, int)
#define HCISETSCAN _IOW('H', 221, int)

static int vhci_fd = -1;

static void rfkill_unblock_all()
{
	int fd = open("/dev/rfkill", O_WRONLY);
	if (fd < 0)
		fail("open /dev/rfkill failed");
	struct rfkill_event event = {0};
	event.idx = 0;
	event.type = RFKILL_TYPE_ALL;
	event.op = RFKILL_OP_CHANGE_ALL;
	event.soft = 0;
	event.hard = 0;
	if (write(fd, &event, sizeof(event)) < 0)
		fail("write rfkill event failed");
	close(fd);
}

static void hci_send_event_packet(int fd, uint8 evt, void* data, size_t data_len)
{
	struct iovec iv[3];

	struct hci_event_hdr hdr;
	hdr.evt = evt;
	hdr.plen = data_len;

	uint8 type = HCI_EVENT_PKT;

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = &hdr;
	iv[1].iov_len = sizeof(hdr);
	iv[2].iov_base = data;
	iv[2].iov_len = data_len;

	if (writev(fd, iv, sizeof(iv) / sizeof(struct iovec)) < 0)
		fail("writev failed");
}

static void hci_send_event_cmd_complete(int fd, uint16 opcode, void* data, size_t data_len)
{
	struct iovec iv[4];

	struct hci_event_hdr hdr;
	hdr.evt = HCI_EV_CMD_COMPLETE;
	hdr.plen = sizeof(struct hci_ev_cmd_complete) + data_len;

	struct hci_ev_cmd_complete evt_hdr;
	evt_hdr.ncmd = 1;
	evt_hdr.opcode = opcode;

	uint8 type = HCI_EVENT_PKT;

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = &hdr;
	iv[1].iov_len = sizeof(hdr);
	iv[2].iov_base = &evt_hdr;
	iv[2].iov_len = sizeof(evt_hdr);
	iv[3].iov_base = data;
	iv[3].iov_len = data_len;

	if (writev(fd, iv, sizeof(iv) / sizeof(struct iovec)) < 0)
		fail("writev failed");
}

static bool process_command_pkt(int fd, char* buf, ssize_t buf_size)
{
	struct hci_command_hdr* hdr = (struct hci_command_hdr*)buf;
	if (buf_size < (ssize_t)sizeof(struct hci_command_hdr) ||
	    hdr->plen != buf_size - sizeof(struct hci_command_hdr))
		failmsg("process_command_pkt: invalid size", "suze=%zx", buf_size);

	switch (hdr->opcode) {
	case HCI_OP_WRITE_SCAN_ENABLE: {
		uint8 status = 0;
		hci_send_event_cmd_complete(fd, hdr->opcode, &status, sizeof(status));
		return true;
	}
	case HCI_OP_READ_BD_ADDR: {
		struct hci_rp_read_bd_addr rp = {0};
		rp.status = 0;
		memset(&rp.bdaddr, 0xaa, 6);
		hci_send_event_cmd_complete(fd, hdr->opcode, &rp, sizeof(rp));
		return false;
	}
	case HCI_OP_READ_BUFFER_SIZE: {
		struct hci_rp_read_buffer_size rp = {0};
		rp.status = 0;
		rp.acl_mtu = 1021;
		rp.sco_mtu = 96;
		rp.acl_max_pkt = 4;
		rp.sco_max_pkt = 6;
		hci_send_event_cmd_complete(fd, hdr->opcode, &rp, sizeof(rp));
		return false;
	}
	}

	char dummy[0xf9] = {0};
	hci_send_event_cmd_complete(fd, hdr->opcode, dummy, sizeof(dummy));
	return false;
}

static void* event_thread(void* arg)
{
	while (1) {
		char buf[1024] = {0};
		ssize_t buf_size = read(vhci_fd, buf, sizeof(buf));
		if (buf_size < 0)
			fail("read failed");
		debug_dump_data(buf, buf_size);
		if (buf_size > 0 && buf[0] == HCI_COMMAND_PKT) {
			if (process_command_pkt(vhci_fd, buf + 1, buf_size - 1))
				break;
		}
	}
	return NULL;
}

// Matches hci_handles in sys/linux/dev_vhci.txt.
#define HCI_HANDLE_1 200
#define HCI_HANDLE_2 201

#define HCI_PRIMARY 0
#define HCI_OP_RESET 0x0c03

static void initialize_vhci()
{
#if SYZ_EXECUTOR
	if (!flag_vhci_injection)
		return;
#endif

	int hci_sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (hci_sock < 0)
		fail("socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI) failed");

	vhci_fd = open("/dev/vhci", O_RDWR);
	if (vhci_fd == -1)
		fail("open /dev/vhci failed");

	// Remap vhci onto higher fd number to hide it from fuzzer and to keep
	// fd numbers stable regardless of whether vhci is opened or not (also see kMaxFd).
	const int kVhciFd = 202;
	if (dup2(vhci_fd, kVhciFd) < 0)
		fail("dup2(vhci_fd, kVhciFd) failed");
	close(vhci_fd);
	vhci_fd = kVhciFd;

	struct vhci_vendor_pkt_request vendor_pkt_req = {HCI_VENDOR_PKT, HCI_PRIMARY};
	if (write(vhci_fd, &vendor_pkt_req, sizeof(vendor_pkt_req)) != sizeof(vendor_pkt_req))
		fail("vendor_pkt_req write failed");

	struct vhci_pkt vhci_pkt;
	if (read(vhci_fd, &vhci_pkt, sizeof(vhci_pkt)) != sizeof(vhci_pkt))
		fail("vhci_pkt read failed");

	if (vhci_pkt.type == HCI_COMMAND_PKT && vhci_pkt.command_hdr.opcode == HCI_OP_RESET) {
		char response[1] = {0};
		hci_send_event_cmd_complete(vhci_fd, HCI_OP_RESET, response, sizeof(response));

		if (read(vhci_fd, &vhci_pkt, sizeof(vhci_pkt)) != sizeof(vhci_pkt))
			fail("vhci_pkt read failed");
	}

	if (vhci_pkt.type != HCI_VENDOR_PKT)
		fail("wrong response packet");

	int dev_id = vhci_pkt.vendor_pkt.id;
	debug("hci dev id: %x\n", dev_id);

	pthread_t th;
	if (pthread_create(&th, NULL, event_thread, NULL))
		fail("pthread_create failed");

	// Bring hci device up
	int ret = ioctl(hci_sock, HCIDEVUP, dev_id);
	if (ret) {
		if (errno == ERFKILL) {
			rfkill_unblock_all();
			ret = ioctl(hci_sock, HCIDEVUP, dev_id);
		}

		if (ret && errno != EALREADY)
			fail("ioctl(HCIDEVUP) failed");
	}

	// Activate page scanning mode which is required to fake a connection.
	struct hci_dev_req dr = {0};
	dr.dev_id = dev_id;
	dr.dev_opt = SCAN_PAGE;
	if (ioctl(hci_sock, HCISETSCAN, &dr))
		fail("ioctl(HCISETSCAN) failed");

	// Fake a connection with bd address 10:aa:aa:aa:aa:aa.
	// This is a fixed address used in sys/linux/socket_bluetooth.txt.
	struct hci_ev_conn_request request;
	memset(&request, 0, sizeof(request));
	memset(&request.bdaddr, 0xaa, 6);
	*(uint8*)&request.bdaddr.b[5] = 0x10;
	request.link_type = ACL_LINK;
	hci_send_event_packet(vhci_fd, HCI_EV_CONN_REQUEST, &request, sizeof(request));

	struct hci_ev_conn_complete complete;
	memset(&complete, 0, sizeof(complete));
	complete.status = 0;
	complete.handle = HCI_HANDLE_1;
	memset(&complete.bdaddr, 0xaa, 6);
	*(uint8*)&complete.bdaddr.b[5] = 0x10;
	complete.link_type = ACL_LINK;
	complete.encr_mode = 0;
	hci_send_event_packet(vhci_fd, HCI_EV_CONN_COMPLETE, &complete, sizeof(complete));

	struct hci_ev_remote_features features;
	memset(&features, 0, sizeof(features));
	features.status = 0;
	features.handle = HCI_HANDLE_1;
	hci_send_event_packet(vhci_fd, HCI_EV_REMOTE_FEATURES, &features, sizeof(features));

	// Fake a low-energy connection with bd address 11:aa:aa:aa:aa:aa.
	// This is a fixed address used in sys/linux/socket_bluetooth.txt.
	struct {
		struct hci_ev_le_meta le_meta;
		struct hci_ev_le_conn_complete le_conn;
	} le_conn;
	memset(&le_conn, 0, sizeof(le_conn));
	le_conn.le_meta.subevent = HCI_EV_LE_CONN_COMPLETE;
	memset(&le_conn.le_conn.bdaddr, 0xaa, 6);
	*(uint8*)&le_conn.le_conn.bdaddr.b[5] = 0x11;
	le_conn.le_conn.role = 1;
	le_conn.le_conn.handle = HCI_HANDLE_2;
	hci_send_event_packet(vhci_fd, HCI_EV_LE_META, &le_conn, sizeof(le_conn));

	pthread_join(th, NULL);
	close(hci_sock);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_emit_vhci && SYZ_VHCI_INJECTION
static long syz_emit_vhci(volatile long a0, volatile long a1)
{
	if (vhci_fd < 0)
		return (uintptr_t)-1;

	char* data = (char*)a0;
	uint32 length = a1;

	return write(vhci_fd, data, length);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_genetlink_get_family_id
#include <errno.h>
#include <sys/socket.h>

static long syz_genetlink_get_family_id(volatile long name, volatile long sock_arg)
{
	debug("syz_genetlink_get_family_id(%s, %d)\n", (char*)name, (int)sock_arg);
	int fd = sock_arg;
	if (fd < 0) {
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
		if (fd == -1) {
			debug("syz_genetlink_get_family_id: socket failed: %d\n", errno);
			return -1;
		}
	}
	struct nlmsg nlmsg_tmp;
	int ret = netlink_query_family_id(&nlmsg_tmp, fd, (char*)name, false);
	if ((int)sock_arg < 0)
		close(fd);
	if (ret < 0) {
		debug("syz_genetlink_get_family_id: netlink_query_family_id failed: %d\n", ret);
		return -1;
	}

	return ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mount_image || __NR_syz_read_part_table
#include "common_zlib.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

// Setup the loop device needed for mounting a filesystem image. Takes care of
// creating and initializing the underlying file backing the loop device and
// returns the fds to the file and device.
// Returns 0 on success, -1 otherwise.
static int setup_loop_device(unsigned char* data, unsigned long size, const char* loopname, int* loopfd_p)
{
	int err = 0, loopfd = -1;
	int memfd = syscall(__NR_memfd_create, "syzkaller", 0);
	if (memfd == -1) {
		err = errno;
		goto error;
	}
	if (puff_zlib_to_file(data, size, memfd)) {
		err = errno;
		debug("setup_loop_device: could not decompress data: %d\n", errno);
		goto error_close_memfd;
	}

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

	close(memfd);
	*loopfd_p = loopfd;
	return 0;

error_close_loop:
	close(loopfd);
error_close_memfd:
	close(memfd);
error:
	errno = err;
	return -1;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_read_part_table
// syz_read_part_table(size len[img], img ptr[in, compressed_image])
static long syz_read_part_table(volatile unsigned long size, volatile long image)
{
	unsigned char* data = (unsigned char*)image;
	int err = 0, res = -1, loopfd = -1;
	char loopname[64];

	snprintf(loopname, sizeof(loopname), "/dev/loop%llu", procid);
	if (setup_loop_device(data, size, loopname, &loopfd) == -1)
		return -1;

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
	for (unsigned long i = 1, j = 0; i < 8; i++) {
		snprintf(loopname, sizeof(loopname), "/dev/loop%llup%d", procid, (int)i);
		struct stat statbuf;
		if (stat(loopname, &statbuf) == 0) {
			char linkname[64];
			snprintf(linkname, sizeof(linkname), "./file%d", (int)j++);
			if (symlink(loopname, linkname)) {
				debug("syz_read_part_table: symlink(%s, %s) failed: %d\n", loopname, linkname, errno);
			}
		}
	}
error_clear_loop:
	if (res)
		ioctl(loopfd, LOOP_CLR_FD, 0);
	close(loopfd);
	errno = err;
	return res;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_mount_image
#include <stddef.h>
#include <string.h>
#include <sys/mount.h>

// syz_mount_image(
// 	fs ptr[in, string[fs]],
// 	dir ptr[in, filename],
// 	flags flags[mount_flags],
// 	opts ptr[in, fs_options],
// 	chdir bool8,
// 	size len[img],
// 	img ptr[in, compressed_image]
// ) fd_dir
static long syz_mount_image(
    volatile long fsarg,
    volatile long dir,
    volatile long flags,
    volatile long optsarg,
    volatile long change_dir,
    volatile unsigned long size,
    volatile long image)
{
	unsigned char* data = (unsigned char*)image;
	int res = -1, err = 0, loopfd = -1, need_loop_device = !!size;
	char* mount_opts = (char*)optsarg;
	char* target = (char*)dir;
	char* fs = (char*)fsarg;
	char* source = NULL;
	char loopname[64];

	if (need_loop_device) {
		// Some filesystems (e.g. FUSE) do not need a backing device or
		// filesystem image.
		memset(loopname, 0, sizeof(loopname));
		snprintf(loopname, sizeof(loopname), "/dev/loop%llu", procid);
		if (setup_loop_device(data, size, loopname, &loopfd) == -1)
			return -1;
		source = loopname;
	}

	mkdir(target, 0777);
	char opts[256];
	memset(opts, 0, sizeof(opts));
	// Leave some space for the additional options we append below.
	if (strlen(mount_opts) > (sizeof(opts) - 32)) {
		debug("ERROR: syz_mount_image parameter optsarg bigger than internal opts\n");
	}
	strncpy(opts, mount_opts, sizeof(opts) - 32);
	if (strcmp(fs, "iso9660") == 0) {
		flags |= MS_RDONLY;
	} else if (strncmp(fs, "ext", 3) == 0) {
		// For ext2/3/4 we have to have errors=continue because the image
		// can contain errors=panic flag and can legally crash kernel.
		bool has_remount_ro = false;
		char* remount_ro_start = strstr(opts, "errors=remount-ro");
		if (remount_ro_start != NULL) {
			// syzkaller can sometimes break the options format, so we have to make sure this option can really be parsed.
			char after = *(remount_ro_start + strlen("errors=remount-ro"));
			char before = remount_ro_start == opts ? '\0' : *(remount_ro_start - 1);
			has_remount_ro = ((before == '\0' || before == ',') && (after == '\0' || after == ','));
		}
		if (strstr(opts, "errors=panic") || !has_remount_ro)
			strcat(opts, ",errors=continue");
	} else if (strcmp(fs, "xfs") == 0) {
		// For xfs we need nouuid because xfs has a global uuids table
		// and if two parallel executors mounts fs with the same uuid, second mount fails.
		strcat(opts, ",nouuid");
	}
	debug("syz_mount_image: size=%llu loop='%s' dir='%s' fs='%s' flags=%llu opts='%s'\n", (uint64)size, loopname, target, fs, (uint64)flags, opts);
#if SYZ_EXECUTOR
	cover_reset(0);
#endif
	res = mount(source, target, fs, flags, opts);
	if (res == -1) {
		debug("syz_mount_image > mount error: %d\n", errno);
		err = errno;
		goto error_clear_loop;
	}
	res = open(target, O_RDONLY | O_DIRECTORY);
	if (res == -1) {
		debug("syz_mount_image > open error: %d\n", errno);
		err = errno;
		goto error_clear_loop;
	}
	if (change_dir) {
		res = chdir(target);
		if (res == -1) {
			debug("syz_mount_image > chdir error: %d\n", errno);
			err = errno;
		}
	}

error_clear_loop:
	if (need_loop_device) {
		ioctl(loopfd, LOOP_CLR_FD, 0);
		close(loopfd);
	}
	errno = err;
	return res;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
// KVM is not yet supported on RISC-V
#if !GOARCH_riscv64 && !GOARCH_arm
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
#elif GOARCH_ppc64 || GOARCH_ppc64le
#include "common_kvm_ppc64.h"
#elif !GOARCH_arm
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	return 0;
}
#endif
#endif
#endif

#if (SYZ_EXECUTOR || SYZ_NET_RESET) && SYZ_EXECUTOR_USES_FORK_SERVER
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
	uint64 entrytable[XT_TABLE_SIZE / sizeof(uint64)];
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
	uint64 entrytable[XT_TABLE_SIZE / sizeof(uint64)];
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
	uint64 entrytable[XT_TABLE_SIZE / sizeof(uint64)];
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
	uint64 entrytable[XT_TABLE_SIZE / sizeof(uint64)];
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
	int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		failmsg("iptable checkpoint: socket(SOCK_STREAM, IPPROTO_TCP) failed", "family=%d", family);
	}
	for (int i = 0; i < num_tables; i++) {
		struct ipt_table_desc* table = &tables[i];
		strcpy(table->info.name, table->name);
		strcpy(table->replace.name, table->name);
		socklen_t optlen = sizeof(table->info);
		if (getsockopt(fd, level, IPT_SO_GET_INFO, &table->info, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			failmsg("iptable checkpoint: getsockopt(IPT_SO_GET_INFO) failed",
				"table=%s, family=%d", table->name, family);
		}
		debug("iptable checkpoint %s/%d: checkpoint entries=%d hooks=%x size=%d\n",
		      table->name, family, table->info.num_entries,
		      table->info.valid_hooks, table->info.size);
		if (table->info.size > sizeof(table->replace.entrytable))
			failmsg("iptable checkpoint: table size is too large", "table=%s, family=%d, size=%u",
				table->name, family, table->info.size);
		if (table->info.num_entries > XT_MAX_ENTRIES)
			failmsg("iptable checkpoint: too many counters", "table=%s, family=%d, counters=%d",
				table->name, family, table->info.num_entries);
		struct ipt_get_entries entries;
		memset(&entries, 0, sizeof(entries));
		strcpy(entries.name, table->name);
		entries.size = table->info.size;
		optlen = sizeof(entries) - sizeof(entries.entrytable) + table->info.size;
		if (getsockopt(fd, level, IPT_SO_GET_ENTRIES, &entries, &optlen))
			failmsg("iptable checkpoint: getsockopt(IPT_SO_GET_ENTRIES) failed",
				"table=%s, family=%d", table->name, family);
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
	int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		failmsg("iptable: socket(SOCK_STREAM, IPPROTO_TCP) failed", "family=%d", family);
	}
	for (int i = 0; i < num_tables; i++) {
		struct ipt_table_desc* table = &tables[i];
		if (table->info.valid_hooks == 0)
			continue;
		struct ipt_getinfo info;
		memset(&info, 0, sizeof(info));
		strcpy(info.name, table->name);
		socklen_t optlen = sizeof(info);
		if (getsockopt(fd, level, IPT_SO_GET_INFO, &info, &optlen))
			failmsg("iptable: getsockopt(IPT_SO_GET_INFO) failed",
				"table=%s, family=%d", table->name, family);
		if (memcmp(&table->info, &info, sizeof(table->info)) == 0) {
			struct ipt_get_entries entries;
			memset(&entries, 0, sizeof(entries));
			strcpy(entries.name, table->name);
			entries.size = table->info.size;
			optlen = sizeof(entries) - sizeof(entries.entrytable) + entries.size;
			if (getsockopt(fd, level, IPT_SO_GET_ENTRIES, &entries, &optlen))
				failmsg("iptable: getsockopt(IPT_SO_GET_ENTRIES) failed",
					"table=%s, family=%d", table->name, family);
			if (memcmp(table->replace.entrytable, entries.entrytable, table->info.size) == 0)
				continue;
		}
		debug("iptable %s/%d: resetting\n", table->name, family);
		struct xt_counters counters[XT_MAX_ENTRIES];
		table->replace.num_counters = info.num_entries;
		table->replace.counters = counters;
		optlen = sizeof(table->replace) - sizeof(table->replace.entrytable) + table->replace.size;
		if (setsockopt(fd, level, IPT_SO_SET_REPLACE, &table->replace, optlen))
			failmsg("iptable: setsockopt(IPT_SO_SET_REPLACE) failed",
				"table=%s, family=%d", table->name, family);
	}
	close(fd);
}

static void checkpoint_arptables(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("arptable checkpoint: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) failed");
	}
	for (unsigned i = 0; i < sizeof(arpt_tables) / sizeof(arpt_tables[0]); i++) {
		struct arpt_table_desc* table = &arpt_tables[i];
		strcpy(table->info.name, table->name);
		strcpy(table->replace.name, table->name);
		socklen_t optlen = sizeof(table->info);
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO, &table->info, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			failmsg("arptable checkpoint: getsockopt(ARPT_SO_GET_INFO) failed", "table=%s", table->name);
		}
		debug("arptable checkpoint %s: entries=%d hooks=%x size=%d\n",
		      table->name, table->info.num_entries, table->info.valid_hooks, table->info.size);
		if (table->info.size > sizeof(table->replace.entrytable))
			failmsg("arptable checkpoint: table size is too large",
				"table=%s, size=%u", table->name, table->info.size);
		if (table->info.num_entries > XT_MAX_ENTRIES)
			failmsg("arptable checkpoint: too many counters",
				"table=%s, counters=%u", table->name, table->info.num_entries);
		struct arpt_get_entries entries;
		memset(&entries, 0, sizeof(entries));
		strcpy(entries.name, table->name);
		entries.size = table->info.size;
		optlen = sizeof(entries) - sizeof(entries.entrytable) + table->info.size;
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES, &entries, &optlen))
			failmsg("arptable checkpoint: getsockopt(ARPT_SO_GET_ENTRIES) failed", "table=%s", table->name);
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
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("arptable: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (unsigned i = 0; i < sizeof(arpt_tables) / sizeof(arpt_tables[0]); i++) {
		struct arpt_table_desc* table = &arpt_tables[i];
		if (table->info.valid_hooks == 0)
			continue;
		struct arpt_getinfo info;
		memset(&info, 0, sizeof(info));
		strcpy(info.name, table->name);
		socklen_t optlen = sizeof(info);
		if (getsockopt(fd, SOL_IP, ARPT_SO_GET_INFO, &info, &optlen))
			failmsg("arptable: getsockopt(ARPT_SO_GET_INFO) failed", "table=%s", table->name);
		if (memcmp(&table->info, &info, sizeof(table->info)) == 0) {
			struct arpt_get_entries entries;
			memset(&entries, 0, sizeof(entries));
			strcpy(entries.name, table->name);
			entries.size = table->info.size;
			optlen = sizeof(entries) - sizeof(entries.entrytable) + entries.size;
			if (getsockopt(fd, SOL_IP, ARPT_SO_GET_ENTRIES, &entries, &optlen))
				failmsg("arptable: getsockopt(ARPT_SO_GET_ENTRIES) failed", "table=%s", table->name);
			if (memcmp(table->replace.entrytable, entries.entrytable, table->info.size) == 0)
				continue;
			debug("arptable %s: data changed\n", table->name);
		} else {
			debug("arptable %s: header changed\n", table->name);
		}
		debug("arptable %s: resetting\n", table->name);
		struct xt_counters counters[XT_MAX_ENTRIES];
		table->replace.num_counters = info.num_entries;
		table->replace.counters = counters;
		optlen = sizeof(table->replace) - sizeof(table->replace.entrytable) + table->replace.size;
		if (setsockopt(fd, SOL_IP, ARPT_SO_SET_REPLACE, &table->replace, optlen))
			failmsg("arptable: setsockopt(ARPT_SO_SET_REPLACE) failed",
				"table=%s", table->name);
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
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("ebtable checkpoint: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (size_t i = 0; i < sizeof(ebt_tables) / sizeof(ebt_tables[0]); i++) {
		struct ebt_table_desc* table = &ebt_tables[i];
		strcpy(table->replace.name, table->name);
		socklen_t optlen = sizeof(table->replace);
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_INFO, &table->replace, &optlen)) {
			switch (errno) {
			case EPERM:
			case ENOENT:
			case ENOPROTOOPT:
				continue;
			}
			failmsg("ebtable checkpoint: getsockopt(EBT_SO_GET_INIT_INFO) failed",
				"table=%s", table->name);
		}
		debug("ebtable checkpoint %s: entries=%d hooks=%x size=%d\n",
		      table->name, table->replace.nentries, table->replace.valid_hooks,
		      table->replace.entries_size);
		if (table->replace.entries_size > sizeof(table->entrytable))
			failmsg("ebtable checkpoint: table size is too large", "table=%s, size=%u",
				table->name, table->replace.entries_size);
		table->replace.num_counters = 0;
		table->replace.entries = table->entrytable;
		optlen = sizeof(table->replace) + table->replace.entries_size;
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INIT_ENTRIES, &table->replace, &optlen))
			failmsg("ebtable checkpoint: getsockopt(EBT_SO_GET_INIT_ENTRIES) failed",
				"table=%s", table->name);
	}
	close(fd);
}

static void reset_ebtables()
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		switch (errno) {
		case EAFNOSUPPORT:
		case ENOPROTOOPT:
			return;
		}
		fail("ebtable: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)");
	}
	for (unsigned i = 0; i < sizeof(ebt_tables) / sizeof(ebt_tables[0]); i++) {
		struct ebt_table_desc* table = &ebt_tables[i];
		if (table->replace.valid_hooks == 0)
			continue;
		struct ebt_replace replace;
		memset(&replace, 0, sizeof(replace));
		strcpy(replace.name, table->name);
		socklen_t optlen = sizeof(replace);
		if (getsockopt(fd, SOL_IP, EBT_SO_GET_INFO, &replace, &optlen))
			failmsg("ebtable: getsockopt(EBT_SO_GET_INFO)", "table=%s", table->name);
		replace.num_counters = 0;
		table->replace.entries = 0;
		for (unsigned h = 0; h < NF_BR_NUMHOOKS; h++)
			table->replace.hook_entry[h] = 0;
		if (memcmp(&table->replace, &replace, sizeof(table->replace)) == 0) {
			char entrytable[XT_TABLE_SIZE];
			memset(&entrytable, 0, sizeof(entrytable));
			replace.entries = entrytable;
			optlen = sizeof(replace) + replace.entries_size;
			if (getsockopt(fd, SOL_IP, EBT_SO_GET_ENTRIES, &replace, &optlen))
				failmsg("ebtable: getsockopt(EBT_SO_GET_ENTRIES) failed", "table=%s", table->name);
			if (memcmp(table->entrytable, entrytable, replace.entries_size) == 0)
				continue;
		}
		debug("ebtable %s: resetting\n", table->name);
		// Kernel does not seem to return actual entry points (wat?).
		for (unsigned j = 0, h = 0; h < NF_BR_NUMHOOKS; h++) {
			if (table->replace.valid_hooks & (1 << h)) {
				table->replace.hook_entry[h] = (struct ebt_entries*)table->entrytable + j;
				j++;
			}
		}
		table->replace.entries = table->entrytable;
		optlen = sizeof(table->replace) + table->replace.entries_size;
		if (setsockopt(fd, SOL_IP, EBT_SO_SET_ENTRIES, &table->replace, optlen))
			failmsg("ebtable: setsockopt(EBT_SO_SET_ENTRIES) failed", "table=%s", table->name);
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
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

static void mount_cgroups(const char* dir, const char** controllers, int count)
{
	if (mkdir(dir, 0777)) {
		debug("mkdir(%s) failed: %d\n", dir, errno);
		return;
	}
	// First, probe one-by-one to understand what controllers are present.
	char enabled[128] = {0};
	int i = 0;
	for (; i < count; i++) {
		if (mount("none", dir, "cgroup", 0, controllers[i])) {
			debug("mount(%s, %s) failed: %d\n", dir, controllers[i], errno);
			continue;
		}
		umount(dir);
		strcat(enabled, ",");
		strcat(enabled, controllers[i]);
	}
	if (enabled[0] == 0) {
		if (rmdir(dir) && errno != EBUSY)
			failmsg("rmdir failed", "dir=%s", dir);
		return;
	}
	// Now mount all at once.
	if (mount("none", dir, "cgroup", 0, enabled + 1)) {
		// In systemd/stretch images this is failing with EBUSY
		// (systemd starts messing with these mounts?),
		// so we don't fail, but just log the error.
		debug("mount(%s, %s) failed: %d\n", dir, enabled + 1, errno);
		if (rmdir(dir) && errno != EBUSY)
			failmsg("rmdir failed", "dir=%s enabled=%s", dir, enabled);
	}
	if (chmod(dir, 0777)) {
		debug("chmod(%s) failed: %d\n", dir, errno);
	}
}

static void mount_cgroups2(const char** controllers, int count)
{
	if (mkdir("/syzcgroup/unified", 0777)) {
		debug("mkdir(/syzcgroup/unified) failed: %d\n", errno);
		return;
	}
	if (mount("none", "/syzcgroup/unified", "cgroup2", 0, NULL)) {
		debug("mount(cgroup2) failed: %d\n", errno);
		// For all cases when we don't end up mounting cgroup/cgroup2
		// in /syzcgroup/{unified,net,cpu}, we need to remove the dir.
		// Otherwise these will end up as normal dirs and the fuzzer may
		// create huge files there. These files won't be cleaned up
		// after tests and may easily consume all disk space.
		// EBUSY usually means that cgroup is already mounted there
		// by a previous run of e.g. syz-execprog.
		if (rmdir("/syzcgroup/unified") && errno != EBUSY)
			fail("rmdir(/syzcgroup/unified) failed");
		return;
	}
	if (chmod("/syzcgroup/unified", 0777)) {
		debug("chmod(/syzcgroup/unified) failed: %d\n", errno);
	}
	int control = open("/syzcgroup/unified/cgroup.subtree_control", O_WRONLY);
	if (control == -1)
		return;
	int i;
	for (i = 0; i < count; i++)
		if (write(control, controllers[i], strlen(controllers[i])) < 0) {
			debug("write(cgroup.subtree_control, %s) failed: %d\n", controllers[i], errno);
		}
	close(control);
}

static void setup_cgroups()
{
	// We want to cover both cgroup and cgroup2.
	// Each resource controller can be bound to only one of them,
	// so to cover both we divide all controllers into 3 arbitrary groups.
	// One group is then bound to cgroup2/unified, and 2 other groups
	// are bound to 2 cgroup hierarchies.
	// Note: we need to enable controllers one-by-one for both cgroup and cgroup2.
	// If we enable all at the same time and one of them fails (b/c of older kernel
	// or not enabled configs), then all will fail.
	const char* unified_controllers[] = {"+cpu", "+memory", "+io", "+pids"};
	const char* net_controllers[] = {"net", "net_prio", "devices", "blkio", "freezer"};
	const char* cpu_controllers[] = {"cpuset", "cpuacct", "hugetlb", "rlimit"};
	if (mkdir("/syzcgroup", 0777)) {
		// Can happen due to e.g. read-only file system (EROFS).
		debug("mkdir(/syzcgroup) failed: %d\n", errno);
		return;
	}
	mount_cgroups2(unified_controllers, sizeof(unified_controllers) / sizeof(unified_controllers[0]));
	mount_cgroups("/syzcgroup/net", net_controllers, sizeof(net_controllers) / sizeof(net_controllers[0]));
	mount_cgroups("/syzcgroup/cpu", cpu_controllers, sizeof(cpu_controllers) / sizeof(cpu_controllers[0]));
	write_file("/syzcgroup/cpu/cgroup.clone_children", "1");
	write_file("/syzcgroup/cpu/cpuset.memory_pressure_enabled", "1");
}

#if (SYZ_EXECUTOR || SYZ_REPEAT) && SYZ_EXECUTOR_USES_FORK_SERVER
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
static void initialize_cgroups()
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
#include <sys/stat.h>
#include <unistd.h>

static void setup_common()
{
	if (mount(0, "/sys/fs/fuse/connections", "fusectl", 0, 0)) {
		debug("mount(fusectl) failed: %d\n", errno);
	}
}

static void setup_binderfs()
{
	// NOTE: this function must be called after chroot.
	// Bind an instance of binderfs specific just to this executor - it will
	// only be visible in its mount namespace and will help isolate binder
	// devices during fuzzing.
	// These commands will just silently fail if binderfs is not supported.
	// Ideally it should have been added as a separate feature (with lots of
	// minor changes throughout the code base), but it seems to be an overkill
	// for just 2 simple lines of code.
	if (mkdir("/dev/binderfs", 0777)) {
		debug("mkdir(/dev/binderfs) failed: %d\n", errno);
	}

	if (mount("binder", "/dev/binderfs", "binder", 0, NULL)) {
		debug("mount of binder at /dev/binderfs failed: %d\n", errno);
	}
#if !SYZ_EXECUTOR && !SYZ_USE_TMP_DIR
	// Do a local symlink right away.
	if (symlink("/dev/binderfs", "./binderfs")) {
		debug("symlink(/dev/binderfs, ./binderfs) failed: %d\n", errno);
	}
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
	// Note: core size is also restricted by RLIMIT_FSIZE.
	rlim.rlim_cur = rlim.rlim_max = 128 << 20;
	setrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 256; // see kMaxFd
	setrlimit(RLIMIT_NOFILE, &rlim);

	// CLONE_NEWNS/NEWCGROUP cause EINVAL on some systems,
	// so we do them separately of clone in do_sandbox_namespace.
	if (unshare(CLONE_NEWNS)) {
		debug("unshare(CLONE_NEWNS): %d\n", errno);
	}
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		debug("mount(\"/\", MS_REC | MS_PRIVATE): %d\n", errno);
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
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE
static int wait_for_loop(int pid)
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

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID
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
#if SYZ_EXECUTOR || SYZ_VHCI_INJECTION
	initialize_vhci();
#endif
	sandbox_common();
	drop_caps();
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices_init();
#endif
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
	// Enable access to IPPROTO_ICMP sockets, must be done after CLONE_NEWNET.
	write_file("/proc/sys/net/ipv4/ping_group_range", "0 65535");
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
	initialize_devlink_pci();
#endif
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices();
#endif
#if SYZ_EXECUTOR || SYZ_WIFI
	initialize_wifi_devices();
#endif
	setup_binderfs();
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
#if SYZ_EXECUTOR || SYZ_VHCI_INJECTION
	initialize_vhci();
#endif
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
#if SYZ_EXECUTOR || SYZ_WIFI
	initialize_wifi_devices();
#endif
	setup_binderfs();

	const int nobody = 65534;
	if (setgroups(0, NULL))
		fail("failed to setgroups");
	if (syscall(SYS_setresgid, nobody, nobody, nobody))
		fail("failed to setresgid");
	if (syscall(SYS_setresuid, nobody, nobody, nobody))
		fail("failed to setresuid");

	// setresuid and setresgid clear the parent-death signal.
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	// This is required to open /proc/self/ files.
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
	// Enable access to IPPROTO_ICMP sockets, must be done after CLONE_NEWNET.
	write_file("/proc/sys/net/ipv4/ping_group_range", "0 65535");
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
#if SYZ_EXECUTOR || SYZ_WIFI
	initialize_wifi_devices();
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
	setup_binderfs();
	drop_caps();

	loop();
	doexit(1);
}

#define SYZ_HAVE_SANDBOX_NAMESPACE 1
static int do_sandbox_namespace(void)
{
	setup_common();
#if SYZ_EXECUTOR || SYZ_VHCI_INJECTION
	// HCIDEVUP requires CAP_ADMIN, so this needs to happen early.
	initialize_vhci();
#endif
	real_uid = getuid();
	real_gid = getgid();
	mprotect(sandbox_stack, 4096, PROT_NONE); // to catch stack underflows
	int pid = clone(namespace_sandbox_proc, &sandbox_stack[sizeof(sandbox_stack) - 64],
			CLONE_NEWUSER | CLONE_NEWPID, 0);
	return wait_for_loop(pid);
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_ANDROID
// seccomp only supported for Arm, Arm64, X86, and X86_64 archs
#if GOARCH_arm || GOARCH_arm64 || GOARCH_386 || GOARCH_amd64
#include <assert.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "android/android_seccomp.h"

#if GOARCH_amd64 || GOARCH_386
// Syz-executor is linked against glibc when fuzzing runs on Cuttlefish x86-x64.
// However Android blocks calls into mkdir, rmdir, symlink which causes
// syz-executor to crash. When fuzzing runs on Android device this issue
// is not observed, because syz-executor is linked against Bionic. Under
// the hood Bionic invokes mkdirat, inlinkat and symlinkat, which are
// allowed by seccomp-bpf.
// This issue may exist not only in Android, but also in Linux in general
// where seccomp filtering is enforced.
//
// This trick makes linker believe it matched the correct version of mkdir,
// rmdir, symlink. So now behavior is the same across ARM and non-ARM builds.
inline int mkdir(const char* path, mode_t mode)
{
	return mkdirat(AT_FDCWD, path, mode);
}

inline int rmdir(const char* path)
{
	return unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

inline int symlink(const char* old_path, const char* new_path)
{
	return symlinkat(old_path, AT_FDCWD, new_path);
}
#endif

#endif
#include <fcntl.h> // open(2)
#include <grp.h> // setgroups
#include <sys/xattr.h> // setxattr, getxattr

#define AID_NET_BT_ADMIN 3001
#define AID_NET_BT 3002
#define AID_INET 3003
#define AID_EVERYBODY 9997
#define AID_APP 10000

#define UNTRUSTED_APP_UID (AID_APP + 999)
#define UNTRUSTED_APP_GID (AID_APP + 999)

#define SYSTEM_UID 1000
#define SYSTEM_GID 1000

const char* const SELINUX_CONTEXT_UNTRUSTED_APP = "u:r:untrusted_app:s0:c512,c768";
const char* const SELINUX_LABEL_APP_DATA_FILE = "u:object_r:app_data_file:s0:c512,c768";
const char* const SELINUX_CONTEXT_FILE = "/proc/thread-self/attr/current";
const char* const SELINUX_XATTR_NAME = "security.selinux";

const gid_t UNTRUSTED_APP_GROUPS[] = {UNTRUSTED_APP_GID, AID_NET_BT_ADMIN, AID_NET_BT, AID_INET, AID_EVERYBODY};
const size_t UNTRUSTED_APP_NUM_GROUPS = sizeof(UNTRUSTED_APP_GROUPS) / sizeof(UNTRUSTED_APP_GROUPS[0]);

const gid_t SYSTEM_GROUPS[] = {SYSTEM_GID, AID_NET_BT_ADMIN, AID_NET_BT, AID_INET, AID_EVERYBODY};
const size_t SYSTEM_NUM_GROUPS = sizeof(SYSTEM_GROUPS) / sizeof(SYSTEM_GROUPS[0]);

// Similar to libselinux getcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void getcon(char* context, size_t context_size)
{
	int fd = open(SELINUX_CONTEXT_FILE, O_RDONLY);
	if (fd < 0)
		fail("getcon: couldn't open context file");

	ssize_t nread = read(fd, context, context_size);

	close(fd);

	if (nread <= 0)
		fail("getcon: failed to read context file");

	// The contents of the context file MAY end with a newline
	// and MAY not have a null terminator.  Handle this here.
	if (context[nread - 1] == '\n')
		context[nread - 1] = '\0';
}

// Similar to libselinux setcon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void setcon(const char* context)
{
	char new_context[512];

	// Attempt to write the new context
	int fd = open(SELINUX_CONTEXT_FILE, O_WRONLY);

	if (fd < 0)
		fail("setcon: could not open context file");

	ssize_t bytes_written = write(fd, context, strlen(context));

	// N.B.: We cannot reuse this file descriptor, since the target SELinux context
	//       may not be able to read from it.
	close(fd);

	if (bytes_written != (ssize_t)strlen(context))
		failmsg("setcon: could not write entire context", "wrote=%zi, expected=%zu", bytes_written, strlen(context));

	// Validate the transition by checking the context
	getcon(new_context, sizeof(new_context));

	if (strcmp(context, new_context) != 0)
		failmsg("setcon: failed to change", "want=%s, context=%s", context, new_context);
}

// Similar to libselinux setfilecon(3), but:
// - No library dependency
// - No dynamic memory allocation
// - Uses fail() instead of returning an error code
static void setfilecon(const char* path, const char* context)
{
	char new_context[512];

	if (setxattr(path, SELINUX_XATTR_NAME, context, strlen(context) + 1, 0) != 0)
		fail("setfilecon: setxattr failed");
	if (getxattr(path, SELINUX_XATTR_NAME, new_context, sizeof(new_context)) < 0)
		fail("setfilecon: getxattr failed");
	if (strcmp(context, new_context) != 0)
		failmsg("setfilecon: could not set context", "want=%s, got=%s", context, new_context);
}

#define SYZ_HAVE_SANDBOX_ANDROID 1

static int do_sandbox_android(uint64 sandbox_arg)
{
	setup_common();
#if SYZ_EXECUTOR || SYZ_VHCI_INJECTION
	initialize_vhci();
#endif
	sandbox_common();
	drop_caps();

#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices_init();
#endif
	// CLONE_NEWNET must always happen before tun setup, because we want the tun
	// device in the test namespace. If we don't do this, executor will crash with
	// SYZFATAL: executor NUM failed NUM times: executor NUM: EOF
	if (unshare(CLONE_NEWNET)) {
		debug("unshare(CLONE_NEWNET): %d\n", errno);
	}
	// Enable access to IPPROTO_ICMP sockets, must be done after CLONE_NEWNET.
	write_file("/proc/sys/net/ipv4/ping_group_range", "0 65535");
#if SYZ_EXECUTOR || SYZ_DEVLINK_PCI
	initialize_devlink_pci();
#endif
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun();
#endif
#if SYZ_EXECUTOR || SYZ_NET_DEVICES
	initialize_netdevices();
#endif
	uid_t uid = UNTRUSTED_APP_UID;
	size_t num_groups = UNTRUSTED_APP_NUM_GROUPS;
	const gid_t* groups = UNTRUSTED_APP_GROUPS;
	gid_t gid = UNTRUSTED_APP_GID;
	debug("executor received sandbox_arg=%llu\n", sandbox_arg);
	if (sandbox_arg == 1) {
		uid = SYSTEM_UID;
		num_groups = SYSTEM_NUM_GROUPS;
		groups = SYSTEM_GROUPS;
		gid = SYSTEM_GID;

		debug("fuzzing under SYSTEM account\n");
	}
	if (chown(".", uid, uid) != 0)
		failmsg("do_sandbox_android: chmod failed", "sandbox_arg=%llu", sandbox_arg);

	if (setgroups(num_groups, groups) != 0)
		failmsg("do_sandbox_android: setgroups failed", "sandbox_arg=%llu", sandbox_arg);

	if (setresgid(gid, gid, gid) != 0)
		failmsg("do_sandbox_android: setresgid failed", "sandbox_arg=%llu", sandbox_arg);

	setup_binderfs();

#if GOARCH_arm || GOARCH_arm64 || GOARCH_386 || GOARCH_amd64
	// Will fail() if anything fails.
	// Must be called when the new process still has CAP_SYS_ADMIN, in this case,
	// before changing uid from 0, which clears capabilities.
	int account = SCFS_RestrictedApp;
	if (sandbox_arg == 1)
		account = SCFS_SystemAccount;
	set_app_seccomp_filter(account);
#endif

	if (setresuid(uid, uid, uid) != 0)
		failmsg("do_sandbox_android: setresuid failed", "sandbox_arg=%llu", sandbox_arg);

	// setresuid and setresgid clear the parent-death signal.
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

	setfilecon(".", SELINUX_LABEL_APP_DATA_FILE);
	if (uid == UNTRUSTED_APP_UID)
		setcon(SELINUX_CONTEXT_UNTRUSTED_APP);

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
	int iter = 0;
	DIR* dp = 0;
retry:
#if SYZ_EXECUTOR || !SYZ_SANDBOX_ANDROID
#if SYZ_EXECUTOR
	if (!flag_sandbox_android)
#endif
		while (umount2(dir, MNT_DETACH | UMOUNT_NOFOLLOW) == 0) {
			debug("umount(%s)\n", dir);
		}
#endif
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
	struct dirent* ep = 0;
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char filename[FILENAME_MAX];
		snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);
		// If it's 9p mount with broken transport, lstat will fail.
		// So try to umount first.
#if SYZ_EXECUTOR || !SYZ_SANDBOX_ANDROID
#if SYZ_EXECUTOR
		if (!flag_sandbox_android)
#endif
			while (umount2(filename, MNT_DETACH | UMOUNT_NOFOLLOW) == 0) {
				debug("umount(%s)\n", filename);
			}
#endif
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
#if SYZ_EXECUTOR || !SYZ_SANDBOX_ANDROID
#if SYZ_EXECUTOR
			if (!flag_sandbox_android) {
#endif
				debug("umount(%s)\n", filename);
				if (umount2(filename, MNT_DETACH | UMOUNT_NOFOLLOW))
					exitf("umount(%s) failed", filename);
#if SYZ_EXECUTOR
			}
#endif
#endif
		}
	}
	closedir(dp);
	for (int i = 0;; i++) {
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
#if SYZ_EXECUTOR || !SYZ_SANDBOX_ANDROID
#if SYZ_EXECUTOR
				if (!flag_sandbox_android) {
#endif
					debug("umount(%s)\n", dir);
					if (umount2(dir, MNT_DETACH | UMOUNT_NOFOLLOW))
						exitf("umount(%s) failed", dir);
#if SYZ_EXECUTOR
				}
#endif
#endif
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
	sprintf(buf, "%d", nth);
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

#if (SYZ_EXECUTOR || SYZ_REPEAT) && SYZ_EXECUTOR_USES_FORK_SERVER
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
	// First, give it up to 100 ms to surrender.
	for (int i = 0; i < 100; i++) {
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

#if (SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_CGROUPS || SYZ_NET_RESET)) && SYZ_EXECUTOR_USES_FORK_SERVER
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

#if (SYZ_EXECUTOR || SYZ_REPEAT && (SYZ_NET_RESET || __NR_syz_mount_image || __NR_syz_read_part_table)) && SYZ_EXECUTOR_USES_FORK_SERVER
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

#if (SYZ_EXECUTOR || SYZ_REPEAT) && SYZ_EXECUTOR_USES_FORK_SERVER
#include <sys/prctl.h>
#include <unistd.h>

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
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
	// Add a binderfs symlink to the tmp folder.
	if (symlink("/dev/binderfs", "./binderfs")) {
		debug("symlink(/dev/binderfs, ./binderfs) failed: %d", errno);
	}
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
	for (int fd = 3; fd < MAX_FDS; fd++)
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
				failmsg("failed to write fault injection file", "file=%s", files[i].file);
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
		fail("failed to write(kmemleak, \"scan\")");
	sleep(5); // account for MSECS_MIN_AGE
	if (!write_file(KMEMLEAK_FILE, "scan"))
		fail("failed to write(kmemleak, \"scan\")");
	if (!write_file(KMEMLEAK_FILE, "clear"))
		fail("failed to write(kmemleak, \"clear\")");
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
		fail("failed to open(kmemleak)");
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
		fail("failed to write(kmemleak, \"scan\")");
	sleep(1);
	// Account for MSECS_MIN_AGE
	// (1 second less because scanning will take at least a second).
	while (current_time_ms() - start < 4 * 1000)
		sleep(1);
	if (write(fd, "scan", 4) != 4)
		fail("failed to write(kmemleak, \"scan\")");
	static char buf[128 << 10];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		fail("failed to read(kmemleak)");
	int nleaks = 0;
	if (n != 0) {
		sleep(1);
		if (write(fd, "scan", 4) != 4)
			fail("failed to write(kmemleak, \"scan\")");
		if (lseek(fd, 0, SEEK_SET) < 0)
			fail("failed to lseek(kmemleak)");
		n = read(fd, buf, sizeof(buf) - 1);
		if (n < 0)
			fail("failed to read(kmemleak)");
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
		fail("failed to write(kmemleak, \"clear\")");
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
static void setup_kcsan_filterlist(char** frames, int nframes, bool suppress)
{
	int fd = open(KCSAN_DEBUGFS_FILE, O_WRONLY);
	if (fd == -1)
		fail("failed to open kcsan debugfs file");

	printf("%s KCSAN reports in functions: ",
	       suppress ? "suppressing" : "only showing");
	if (!suppress)
		dprintf(fd, "whitelist\n");
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

#if SYZ_EXECUTOR || SYZ_USB
static void setup_usb()
{
	if (chmod("/dev/raw-gadget", 0666))
		fail("failed to chmod /dev/raw-gadget");
}
#endif

#if SYZ_EXECUTOR || SYZ_SYSCTL
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void setup_sysctl()
{
	char mypid[32];
	snprintf(mypid, sizeof(mypid), "%d", getpid());

	// TODO: consider moving all sysctl's into CMDLINE config later.
	// Kernel has support for setting sysctl's via command line since 3db978d480e28 (v5.8).
	struct {
		const char* name;
		const char* data;
	} files[] = {
#if GOARCH_amd64 || GOARCH_386
		// nmi_check_duration() prints "INFO: NMI handler took too long" on slow debug kernels.
		// It happens a lot in qemu, and the messages are frequently corrupted
		// (intermixed with other kernel output as they are printed from NMI)
		// and are not matched against the suppression in pkg/report.
		// This write prevents these messages from being printed.
		{"/sys/kernel/debug/x86/nmi_longest_ns", "10000000000"},
#endif
		{"/proc/sys/kernel/hung_task_check_interval_secs", "20"},
		// bpf_jit_kallsyms and disabling bpf_jit_harden are required
		// for unwinding through bpf functions.
		{"/proc/sys/net/core/bpf_jit_kallsyms", "1"},
		{"/proc/sys/net/core/bpf_jit_harden", "0"},
		// This is to provide more useful info in crash reports.
		{"/proc/sys/kernel/kptr_restrict", "0"},
		{"/proc/sys/kernel/softlockup_all_cpu_backtrace", "1"},
		// This is to restrict effects of recursive exponential mounts, for details see
		// "mnt: Add a per mount namespace limit on the number of mounts" commit.
		{"/proc/sys/fs/mount-max", "100"},
		// Dumping all tasks to console can take too long.
		{"/proc/sys/vm/oom_dump_tasks", "0"},
		// Executor hits lots of SIGSEGVs, no point in logging them.
		{"/proc/sys/debug/exception-trace", "0"},
		{"/proc/sys/kernel/printk", "7 4 1 3"},
		// Faster gc (1 second) is intended to make tests more repeatable.
		{"/proc/sys/kernel/keys/gc_delay", "1"},
		// We always want to prefer killing the allocating test process rather than somebody else
		// (sshd or another random test process).
		{"/proc/sys/vm/oom_kill_allocating_task", "1"},
		// This blocks some of the ways the fuzzer can trigger a reboot.
		// ctrl-alt-del=0 tells kernel to signal cad_pid instead of rebooting
		// and setting cad_pid to the current pid (transient "syz-executor setup") makes it a no-op.
		// For context see: https://groups.google.com/g/syzkaller-bugs/c/WqOY4TiRnFg/m/6P9u8lWZAQAJ
		{"/proc/sys/kernel/ctrl-alt-del", "0"},
		{"/proc/sys/kernel/cad_pid", mypid},
	};
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (!write_file(files[i].name, files[i].data))
			printf("write to %s failed: %s\n", files[i].name, strerror(errno));
	}
}
#endif

#if SYZ_EXECUTOR || SYZ_802154
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define NL802154_CMD_SET_SHORT_ADDR 11
#define NL802154_ATTR_IFINDEX 3
#define NL802154_ATTR_SHORT_ADDR 10

static void setup_802154()
{
	int sock_route = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock_route == -1)
		fail("socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) failed");
	int sock_generic = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock_generic < 0)
		fail("socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) failed");
	int nl802154_family_id = netlink_query_family_id(&nlmsg, sock_generic, "nl802154", true);
	for (int i = 0; i < 2; i++) {
		// wpan0/1 are created by CONFIG_IEEE802154_HWSIM.
		// sys/linux/socket_ieee802154.txt knowns about these names and consts.
		char devname[] = "wpan0";
		devname[strlen(devname) - 1] += i;
		uint64 hwaddr = 0xaaaaaaaaaaaa0002 + (i << 8);
		uint16 shortaddr = 0xaaa0 + i;
		int ifindex = if_nametoindex(devname);
		struct genlmsghdr genlhdr;
		memset(&genlhdr, 0, sizeof(genlhdr));
		genlhdr.cmd = NL802154_CMD_SET_SHORT_ADDR;
		netlink_init(&nlmsg, nl802154_family_id, 0, &genlhdr, sizeof(genlhdr));
		netlink_attr(&nlmsg, NL802154_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
		netlink_attr(&nlmsg, NL802154_ATTR_SHORT_ADDR, &shortaddr, sizeof(shortaddr));
		int err = netlink_send(&nlmsg, sock_generic);
		if (err < 0) {
			debug("NL802154_CMD_SET_SHORT_ADDR failed: %s\n", strerror(errno));
		}
		netlink_device_change(&nlmsg, sock_route, devname, true, 0, &hwaddr, sizeof(hwaddr), 0);
		if (i == 0) {
			netlink_add_device_impl(&nlmsg, "lowpan", "lowpan0", false);
			netlink_done(&nlmsg);
			netlink_attr(&nlmsg, IFLA_LINK, &ifindex, sizeof(ifindex));
			int err = netlink_send(&nlmsg, sock_route);
			if (err < 0) {
				debug("netlink: adding device lowpan0 type lowpan link wpan0: %s\n", strerror(errno));
			}
		}
	}
	close(sock_route);
	close(sock_generic);
}
#endif

#if GOARCH_s390x
#include <sys/mman.h>
// Ugly way to work around gcc's "error: function called through a non-compatible type".
// Simply casting via (void*) inline does not work b/c gcc sees through a chain of casts.
// The macro is used in generated C code.
#define CAST(f) ({void* p = (void*)f; p; })
#endif

#if SYZ_EXECUTOR || __NR_syz_fuse_handle_req
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

// From linux/fuse.h
#define FUSE_MIN_READ_BUFFER 8192

// From linux/fuse.h
enum fuse_opcode {
	FUSE_LOOKUP = 1,
	FUSE_FORGET = 2, // no reply
	FUSE_GETATTR = 3,
	FUSE_SETATTR = 4,
	FUSE_READLINK = 5,
	FUSE_SYMLINK = 6,
	FUSE_MKNOD = 8,
	FUSE_MKDIR = 9,
	FUSE_UNLINK = 10,
	FUSE_RMDIR = 11,
	FUSE_RENAME = 12,
	FUSE_LINK = 13,
	FUSE_OPEN = 14,
	FUSE_READ = 15,
	FUSE_WRITE = 16,
	FUSE_STATFS = 17,
	FUSE_RELEASE = 18,
	FUSE_FSYNC = 20,
	FUSE_SETXATTR = 21,
	FUSE_GETXATTR = 22,
	FUSE_LISTXATTR = 23,
	FUSE_REMOVEXATTR = 24,
	FUSE_FLUSH = 25,
	FUSE_INIT = 26,
	FUSE_OPENDIR = 27,
	FUSE_READDIR = 28,
	FUSE_RELEASEDIR = 29,
	FUSE_FSYNCDIR = 30,
	FUSE_GETLK = 31,
	FUSE_SETLK = 32,
	FUSE_SETLKW = 33,
	FUSE_ACCESS = 34,
	FUSE_CREATE = 35,
	FUSE_INTERRUPT = 36,
	FUSE_BMAP = 37,
	FUSE_DESTROY = 38,
	FUSE_IOCTL = 39,
	FUSE_POLL = 40,
	FUSE_NOTIFY_REPLY = 41,
	FUSE_BATCH_FORGET = 42,
	FUSE_FALLOCATE = 43,
	FUSE_READDIRPLUS = 44,
	FUSE_RENAME2 = 45,
	FUSE_LSEEK = 46,
	FUSE_COPY_FILE_RANGE = 47,
	FUSE_SETUPMAPPING = 48,
	FUSE_REMOVEMAPPING = 49,

	// CUSE specific operations
	CUSE_INIT = 4096,

	// Reserved opcodes: helpful to detect structure endian-ness
	CUSE_INIT_BSWAP_RESERVED = 1048576, // CUSE_INIT << 8
	FUSE_INIT_BSWAP_RESERVED = 436207616, // FUSE_INIT << 24
};

// From linux/fuse.h
struct fuse_in_header {
	uint32 len;
	uint32 opcode;
	uint64 unique;
	uint64 nodeid;
	uint32 uid;
	uint32 gid;
	uint32 pid;
	uint32 padding;
};

// From linux/fuse.h
struct fuse_out_header {
	uint32 len;
	// This is actually a int32_t but *_t variants fail to compile inside
	// the executor (it appends an additional _t for some reason) and int32
	// does not exist. Since we don't touch this field, defining it as
	// unsigned should not cause any problems.
	uint32 error;
	uint64 unique;
};

// Struct shared between syz_fuse_handle_req() and the fuzzer. Used to provide
// a fuzzed response for each request type.
struct syz_fuse_req_out {
	struct fuse_out_header* init;
	struct fuse_out_header* lseek;
	struct fuse_out_header* bmap;
	struct fuse_out_header* poll;
	struct fuse_out_header* getxattr;
	struct fuse_out_header* lk;
	struct fuse_out_header* statfs;
	struct fuse_out_header* write;
	struct fuse_out_header* read;
	struct fuse_out_header* open;
	struct fuse_out_header* attr;
	struct fuse_out_header* entry;
	struct fuse_out_header* dirent;
	struct fuse_out_header* direntplus;
	struct fuse_out_header* create_open;
	struct fuse_out_header* ioctl;
};

// Link the reponse to the request and send it to /dev/fuse.
static int fuse_send_response(int fd,
			      const struct fuse_in_header* in_hdr,
			      struct fuse_out_header* out_hdr)
{
	if (!out_hdr) {
		debug("fuse_send_response: received a NULL out_hdr\n");
		return -1;
	}

	out_hdr->unique = in_hdr->unique;
	if (write(fd, out_hdr, out_hdr->len) == -1) {
		debug("fuse_send_response > write failed: %d\n", errno);
		return -1;
	}

	return 0;
}

// This function reads a request from /dev/fuse and tries to pick the correct
// response from the input struct syz_fuse_req_out (a3). Responses are still
// generated by the fuzzer.
static volatile long syz_fuse_handle_req(volatile long a0, // /dev/fuse fd.
					 volatile long a1, // Read buffer.
					 volatile long a2, // Buffer len.
					 volatile long a3) // syz_fuse_req_out.
{
	struct syz_fuse_req_out* req_out = (struct syz_fuse_req_out*)a3;
	struct fuse_out_header* out_hdr = NULL;
	char* buf = (char*)a1;
	int buf_len = (int)a2;
	int fd = (int)a0;

	if (!req_out) {
		debug("syz_fuse_handle_req: received a NULL syz_fuse_req_out\n");
		return -1;
	}
	if (buf_len < FUSE_MIN_READ_BUFFER) {
		debug("FUSE requires the read buffer to be at least %u\n", FUSE_MIN_READ_BUFFER);
		return -1;
	}

	int ret = read(fd, buf, buf_len);
	if (ret == -1) {
		debug("syz_fuse_handle_req > read failed: %d\n", errno);
		return -1;
	}
	// Safe to do because ret > 0 (!= -1) and < FUSE_MIN_READ_BUFFER (= 8192).
	if ((size_t)ret < sizeof(struct fuse_in_header)) {
		debug("syz_fuse_handle_req: received a truncated FUSE header\n");
		return -1;
	}

	const struct fuse_in_header* in_hdr = (const struct fuse_in_header*)buf;
	debug("syz_fuse_handle_req: received opcode %d\n", in_hdr->opcode);
	if (in_hdr->len > (uint32)ret) {
		debug("syz_fuse_handle_req: received a truncated message\n");
		return -1;
	}

	switch (in_hdr->opcode) {
	case FUSE_GETATTR:
	case FUSE_SETATTR:
		out_hdr = req_out->attr;
		break;
	case FUSE_LOOKUP:
	case FUSE_SYMLINK:
	case FUSE_LINK:
	case FUSE_MKNOD:
	case FUSE_MKDIR:
		out_hdr = req_out->entry;
		break;
	case FUSE_OPEN:
	case FUSE_OPENDIR:
		out_hdr = req_out->open;
		break;
	case FUSE_STATFS:
		out_hdr = req_out->statfs;
		break;
	case FUSE_RMDIR:
	case FUSE_RENAME:
	case FUSE_RENAME2:
	case FUSE_FALLOCATE:
	case FUSE_SETXATTR:
	case FUSE_REMOVEXATTR:
	case FUSE_FSYNCDIR:
	case FUSE_FSYNC:
	case FUSE_SETLKW:
	case FUSE_SETLK:
	case FUSE_ACCESS:
	case FUSE_FLUSH:
	case FUSE_RELEASE:
	case FUSE_RELEASEDIR:
	case FUSE_UNLINK:
	case FUSE_DESTROY:
		// These opcodes do not have any reply data. Hence, we pick
		// another response and only use the shared header.
		out_hdr = req_out->init;
		if (!out_hdr) {
			debug("syz_fuse_handle_req: received a NULL out_hdr\n");
			return -1;
		}
		out_hdr->len = sizeof(struct fuse_out_header);
		break;
	case FUSE_READ:
		out_hdr = req_out->read;
		break;
	case FUSE_READDIR:
		out_hdr = req_out->dirent;
		break;
	case FUSE_READDIRPLUS:
		out_hdr = req_out->direntplus;
		break;
	case FUSE_INIT:
		out_hdr = req_out->init;
		break;
	case FUSE_LSEEK:
		out_hdr = req_out->lseek;
		break;
	case FUSE_GETLK:
		out_hdr = req_out->lk;
		break;
	case FUSE_BMAP:
		out_hdr = req_out->bmap;
		break;
	case FUSE_POLL:
		out_hdr = req_out->poll;
		break;
	case FUSE_GETXATTR:
	case FUSE_LISTXATTR:
		out_hdr = req_out->getxattr;
		break;
	case FUSE_WRITE:
	case FUSE_COPY_FILE_RANGE:
		out_hdr = req_out->write;
		break;
	case FUSE_FORGET:
	case FUSE_BATCH_FORGET:
		// FUSE_FORGET and FUSE_BATCH_FORGET expect no reply.
		return 0;
	case FUSE_CREATE:
		out_hdr = req_out->create_open;
		break;
	case FUSE_IOCTL:
		out_hdr = req_out->ioctl;
		break;
	default:
		debug("syz_fuse_handle_req: unknown FUSE opcode\n");
		return -1;
	}

	return fuse_send_response(fd, in_hdr, out_hdr);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_80211_inject_frame
#include <linux/genetlink.h>
#include <linux/if_ether.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <sys/ioctl.h>

// This pseudo syscall performs 802.11 frame injection.
//
// Its current implementation performs the injection by means of mac80211_hwsim.
// The procedure consists of the following steps:
// 1. Open a netlink socket
// 2. Register as an application responsible for wireless medium simulation by executing
//    HWSIM_CMD_REGISTER. This is a preq-requisite for the following step. After HWSIM_CMD_REGISTER
//    is executed, mac80211_hwsim stops simulating a perfect medium.
//    It is also important to note that this command registers a specific socket, not a netlink port.
// 3. Inject a frame to the required interface by executing HWSIM_CMD_FRAME.
// 4. Close the socket. mac80211_hwsim will detect this and return to perfect medium simulation.
//
// Note that we cannot (should not) open a socket, register it once and then use it for frame injection
// throughout the lifetime of a proc. When some socket is registered, mac80211_hwsim does not broadcast
// frames to all interfaces itself. As we do not perform this activity either, a permanently registered
// socket will disrupt normal network operation.

#define HWSIM_ATTR_RX_RATE 5
#define HWSIM_ATTR_SIGNAL 6
#define HWSIM_ATTR_ADDR_RECEIVER 1
#define HWSIM_ATTR_FRAME 3

#define WIFI_MAX_INJECT_LEN 2048

static int hwsim_register_socket(struct nlmsg* nlmsg, int sock, int hwsim_family)
{
	struct genlmsghdr genlhdr;
	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = HWSIM_CMD_REGISTER;
	netlink_init(nlmsg, hwsim_family, 0, &genlhdr, sizeof(genlhdr));
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("hwsim_register_device failed: %s\n", strerror(errno));
	}
	return err;
}

static int hwsim_inject_frame(struct nlmsg* nlmsg, int sock, int hwsim_family, uint8* mac_addr, uint8* data, int len)
{
	struct genlmsghdr genlhdr;
	uint32 rx_rate = WIFI_DEFAULT_RX_RATE;
	uint32 signal = WIFI_DEFAULT_SIGNAL;

	memset(&genlhdr, 0, sizeof(genlhdr));
	genlhdr.cmd = HWSIM_CMD_FRAME;
	netlink_init(nlmsg, hwsim_family, 0, &genlhdr, sizeof(genlhdr));
	netlink_attr(nlmsg, HWSIM_ATTR_RX_RATE, &rx_rate, sizeof(rx_rate));
	netlink_attr(nlmsg, HWSIM_ATTR_SIGNAL, &signal, sizeof(signal));
	netlink_attr(nlmsg, HWSIM_ATTR_ADDR_RECEIVER, mac_addr, ETH_ALEN);
	netlink_attr(nlmsg, HWSIM_ATTR_FRAME, data, len);
	int err = netlink_send(nlmsg, sock);
	if (err < 0) {
		debug("hwsim_inject_frame failed: %s\n", strerror(errno));
	}
	return err;
}

static long syz_80211_inject_frame(volatile long a0, volatile long a1, volatile long a2)
{
	uint8* mac_addr = (uint8*)a0;
	uint8* buf = (uint8*)a1;
	int buf_len = (int)a2;
	struct nlmsg tmp_msg;

	if (buf_len < 0 || buf_len > WIFI_MAX_INJECT_LEN) {
		debug("syz_80211_inject_frame: wrong buffer size %d\n", buf_len);
		return -1;
	}

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		debug("syz_80211_inject_frame: socket creation failed, errno %d\n", errno);
		return -1;
	}

	int hwsim_family_id = netlink_query_family_id(&tmp_msg, sock, "MAC80211_HWSIM", true);
	int ret = hwsim_register_socket(&tmp_msg, sock, hwsim_family_id);
	if (ret < 0) {
		debug("syz_80211_inject_frame: failed to register socket, ret %d\n", ret);
		close(sock);
		return -1;
	}

	ret = hwsim_inject_frame(&tmp_msg, sock, hwsim_family_id, mac_addr, buf, buf_len);
	close(sock);
	if (ret < 0) {
		debug("syz_80211_inject_frame: failed to inject message, ret %d\n", ret);
		return -1;
	}

	return 0;
}

#endif

#if SYZ_EXECUTOR || __NR_syz_80211_join_ibss

#define WIFI_MAX_SSID_LEN 32

#define WIFI_JOIN_IBSS_NO_SCAN 0
#define WIFI_JOIN_IBSS_BG_SCAN 1
#define WIFI_JOIN_IBSS_BG_NO_SCAN 2

static long syz_80211_join_ibss(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	char* interface = (char*)a0;
	uint8* ssid = (uint8*)a1;
	int ssid_len = (int)a2;
	int mode = (int)a3; // This parameter essentially determines whether it will perform a scan

	struct nlmsg tmp_msg;
	uint8 bssid[ETH_ALEN] = WIFI_IBSS_BSSID;

	if (ssid_len < 0 || ssid_len > WIFI_MAX_SSID_LEN) {
		debug("syz_80211_join_ibss: invalid ssid len %d\n", ssid_len);
		return -1;
	}

	if (mode < 0 || mode > WIFI_JOIN_IBSS_BG_NO_SCAN) {
		debug("syz_80211_join_ibss: invalid mode %d\n", mode);
		return -1;
	}

	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0) {
		debug("syz_80211_join_ibss: socket creation failed, errno %d\n", errno);
		return -1;
	}

	int nl80211_family_id = netlink_query_family_id(&tmp_msg, sock, "nl80211", true);
	struct join_ibss_props ibss_props = {
	    .wiphy_freq = WIFI_DEFAULT_FREQUENCY,
	    .wiphy_freq_fixed = (mode == WIFI_JOIN_IBSS_NO_SCAN || mode == WIFI_JOIN_IBSS_BG_NO_SCAN),
	    .mac = bssid,
	    .ssid = ssid,
	    .ssid_len = ssid_len};

	int ret = nl80211_setup_ibss_interface(&tmp_msg, sock, nl80211_family_id, interface, &ibss_props);
	close(sock);
	if (ret < 0) {
		debug("syz_80211_join_ibss: failed set up IBSS network for %.32s\n", interface);
		return -1;
	}

	if (mode == WIFI_JOIN_IBSS_NO_SCAN) {
		ret = await_ifla_operstate(&tmp_msg, interface, IF_OPER_UP);
		if (ret < 0) {
			debug("syz_80211_join_ibss: await_ifla_operstate failed for %.32s, ret %d\n", interface, ret);
			return -1;
		}
	}

	return 0;
}

#endif

#if SYZ_EXECUTOR || __NR_syz_clone || __NR_syz_clone3
#if SYZ_EXECUTOR
// The slowdown multiplier is already taken into account.
#define USLEEP_FORKED_CHILD (3 * syscall_timeout_ms * 1000)
#else
#define USLEEP_FORKED_CHILD (3 * /*{{{BASE_CALL_TIMEOUT_MS}}}*/ *1000)
#endif

static long handle_clone_ret(long ret)
{
	if (ret != 0) {
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
		__atomic_store_n(&clone_ongoing, 0, __ATOMIC_RELAXED);
#endif
		return ret;
	}
	// Exit if we're in the child process - not all kernels provide the proper means
	// to prevent fork-bombs.
	// But first sleep for some time. This will hopefully foster IPC fuzzing.
	usleep(USLEEP_FORKED_CHILD);
	// Note that exit_group is a bad choice here because if we created just a thread, then
	// the whole process will be killed. A plain exit will work fine in any case.
	syscall(__NR_exit, 0);
	while (1) {
	}
}
#endif

#if SYZ_EXECUTOR || __NR_syz_clone
#include <sched.h>

// syz_clone is mostly needed on kernels which do not suport clone3.
static long syz_clone(volatile long flags, volatile long stack, volatile long stack_len,
		      volatile long ptid, volatile long ctid, volatile long tls)
{
	// ABI requires 16-byte stack alignment.
	long sp = (stack + stack_len) & ~15;
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
	__atomic_store_n(&clone_ongoing, 1, __ATOMIC_RELAXED);
#endif
	// Clear the CLONE_VM flag. Otherwise it'll very likely corrupt syz-executor.
	long ret = (long)syscall(__NR_clone, flags & ~CLONE_VM, sp, ptid, ctid, tls);
	return handle_clone_ret(ret);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_clone3
#include <linux/sched.h>
#include <sched.h>

#define MAX_CLONE_ARGS_BYTES 256
static long syz_clone3(volatile long a0, volatile long a1)
{
	unsigned long copy_size = a1;
	if (copy_size < sizeof(uint64) || copy_size > MAX_CLONE_ARGS_BYTES)
		return -1;
	// The structure may have different sizes on different kernel versions, so copy it as raw bytes.
	char clone_args[MAX_CLONE_ARGS_BYTES];
	memcpy(&clone_args, (void*)a0, copy_size);

	// As in syz_clone, clear the CLONE_VM flag. Flags are in the first 8-byte integer field.
	uint64* flags = (uint64*)&clone_args;
	*flags &= ~CLONE_VM;
#if SYZ_EXECUTOR || SYZ_HANDLE_SEGV
	__atomic_store_n(&clone_ongoing, 1, __ATOMIC_RELAXED);
#endif
	return handle_clone_ret((long)syscall(__NR_clone3, &clone_args, copy_size));
}

#endif
