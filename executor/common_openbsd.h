// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#include <unistd.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>

// Needed syscall libc stubs.
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#define CAST

#if (SYZ_EXECUTOR || __NR_syz_open_pts)
#include <termios.h>
#include <util.h>

static uintptr_t syz_open_pts(void)
{
	int master, slave;

	if (openpty(&master, &slave, NULL, NULL, NULL) == -1)
		return -1;
	// Move the master fd up in order to reduce the chances of the fuzzer
	// generating a call to close(2) with the same fd.
	if (dup2(master, master + 100) != -1)
		close(master);
	return slave;
}
#endif // (SYZ_EXECUTOR || __NR_syz_open_pts)

#if SYZ_EXECUTOR || SYZ_NET_INJECTION

#include <net/if_tun.h>
#include <sys/types.h>

static int tunfd = -1;

#define MAX_TUN 8

// Because the interface and device name contain an int, use MAXINT to determine
// the maximum size of the string.
// Since on *BSD  sizeof(int) is 4, MAXINT is 2147483647.
#define TUN_IFACE "tap%d"
#define MAX_TUN_IFACE_SIZE sizeof("tap2147483647")
#define TUN_DEVICE "/dev/tap%d"
#define MAX_TUN_DEVICE_SIZE sizeof("/dev/tap2147483647")

#define LOCAL_MAC "aa:aa:aa:aa:aa:aa"
#define REMOTE_MAC "aa:aa:aa:aa:aa:bb"
#define LOCAL_IPV4 "172.20.%d.170"
#define MAX_LOCAL_IPV4_SIZE sizeof("172.20.255.170")
#define REMOTE_IPV4 "172.20.%d.187"
#define MAX_REMOTE_IPV4_SIZE sizeof("172.20.255.187")
#define LOCAL_IPV6 "fe80::%02xaa"
#define MAX_LOCAL_IPV6_SIZE sizeof("fe80::ffaa")
#define REMOTE_IPV6 "fe80::%02xbb"
#define MAX_REMOTE_IPV6_SIZE sizeof("fe80::ffbb")

static void vsnprintf_check(char* str, size_t size, const char* format, va_list args)
{
	int rv = vsnprintf(str, size, format, args);
	if (rv < 0)
		fail("vsnprintf failed");
	if ((size_t)rv >= size)
		failmsg("vsnprintf: string doesn't fit into buffer", "string='%s'", str);
}

static void snprintf_check(char* str, size_t size, const char* format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintf_check(str, size, format, args);
	va_end(args);
}

#define COMMAND_MAX_LEN 128
#define PATH_PREFIX "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "
#define PATH_PREFIX_LEN (sizeof(PATH_PREFIX) - 1)

static void execute_command(bool panic, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	// Executor process does not have any env, including PATH.
	// On some distributions, system/shell adds a minimal PATH, on some it does not.
	// Set own standard PATH to make it work across distributions.
	char command[PATH_PREFIX_LEN + COMMAND_MAX_LEN];
	memcpy(command, PATH_PREFIX, PATH_PREFIX_LEN);
	vsnprintf_check(command + PATH_PREFIX_LEN, COMMAND_MAX_LEN, format, args);
	va_end(args);
	int rv = system(command);
	if (rv) {
		if (panic)
			failmsg("command failed", "command=%s: %d", &command[0], rv);
		debug("command '%s': %d\n", &command[0], rv);
	}
}

static void initialize_tun(int tun_id)
{
#if SYZ_EXECUTOR
	if (!flag_net_injection)
		return;
#endif // SYZ_EXECUTOR

	if (tun_id < 0 || tun_id >= MAX_TUN)
		failmsg("tun_id out of range", "tun_id=%d", tun_id);

	char tun_device[MAX_TUN_DEVICE_SIZE];
	snprintf_check(tun_device, sizeof(tun_device), TUN_DEVICE, tun_id);

	char tun_iface[MAX_TUN_IFACE_SIZE];
	snprintf_check(tun_iface, sizeof(tun_iface), TUN_IFACE, tun_id);

	execute_command(0, "ifconfig %s destroy", tun_iface);

	tunfd = open(tun_device, O_RDWR | O_NONBLOCK);
	if (tunfd == -1) {
#if SYZ_EXECUTOR
		failmsg("tun: can't open device", "device=%s", tun_device);
#else
		printf("tun: can't open %s: errno=%d\n", tun_device, errno);
		return;
#endif // SYZ_EXECUTOR
	}
	// Remap tun onto higher fd number to hide it from fuzzer and to keep
	// fd numbers stable regardless of whether tun is opened or not (also see kMaxFd).
	const int kTunFd = 200;
	if (dup2(tunfd, kTunFd) < 0)
		fail("dup2(tunfd, kTunFd) failed");
	close(tunfd);
	tunfd = kTunFd;

	char local_mac[sizeof(LOCAL_MAC)];
	snprintf_check(local_mac, sizeof(local_mac), LOCAL_MAC);

	// Set the MAC address of the interface to LOCAL_MAC
	execute_command(1, "ifconfig %s lladdr %s", tun_iface, local_mac);

	// Setting up a static ip for the interface
	char local_ipv4[MAX_LOCAL_IPV4_SIZE];
	snprintf_check(local_ipv4, sizeof(local_ipv4), LOCAL_IPV4, tun_id);
	execute_command(1, "ifconfig %s inet %s netmask 255.255.255.0", tun_iface, local_ipv4);

	// Creates an ARP table entry for the remote ip and MAC address
	char remote_mac[sizeof(REMOTE_MAC)];
	char remote_ipv4[MAX_REMOTE_IPV4_SIZE];
	snprintf_check(remote_mac, sizeof(remote_mac), REMOTE_MAC);
	snprintf_check(remote_ipv4, sizeof(remote_ipv4), REMOTE_IPV4, tun_id);
	execute_command(0, "arp -s %s %s", remote_ipv4, remote_mac);

	// Set up a static ipv6 address for the interface
	char local_ipv6[MAX_LOCAL_IPV6_SIZE];
	snprintf_check(local_ipv6, sizeof(local_ipv6), LOCAL_IPV6, tun_id);
	execute_command(1, "ifconfig %s inet6 %s", tun_iface, local_ipv6);

	// Registers an NDP entry for the remote MAC with the remote ipv6 address
	char remote_ipv6[MAX_REMOTE_IPV6_SIZE];
	snprintf_check(remote_ipv6, sizeof(remote_ipv6), REMOTE_IPV6, tun_id);
	execute_command(0, "ndp -s %s%%%s %s", remote_ipv6, tun_iface, remote_mac);
}

#endif // SYZ_EXECUTOR || SYZ_NET_INJECTION

#if SYZ_EXECUTOR || __NR_syz_emit_ethernet && SYZ_NET_INJECTION
#include <sys/uio.h>

static long syz_emit_ethernet(volatile long a0, volatile long a1)
{
	// syz_emit_ethernet(len len[packet], packet ptr[in, array[int8]])
	if (tunfd < 0)
		return (uintptr_t)-1;

	size_t length = a0;
	const char* data = (char*)a1;
	debug_dump_data(data, length);

	return write(tunfd, data, length);
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
		fail("tun: read failed");
	}
	return rv;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_extract_tcp_res && SYZ_NET_INJECTION

struct tcp_resources {
	uint32 seq;
	uint32 ack;
};

#include <net/ethertypes.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

// Include order matters, empty line prevent re-sorting. See a workaround in
// pkg/csource hoistIncludes.
#include <netinet/if_ether.h>

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

	if (length < sizeof(struct ether_header))
		return (uintptr_t)-1;
	struct ether_header* ethhdr = (struct ether_header*)&data[0];

	struct tcphdr* tcphdr = 0;
	if (ethhdr->ether_type == htons(ETHERTYPE_IP)) {
		if (length < sizeof(struct ether_header) + sizeof(struct ip))
			return (uintptr_t)-1;
		struct ip* iphdr = (struct ip*)&data[sizeof(struct ether_header)];
		if (iphdr->ip_p != IPPROTO_TCP)
			return (uintptr_t)-1;
		if (length < sizeof(struct ether_header) + iphdr->ip_hl * 4 + sizeof(struct tcphdr))
			return (uintptr_t)-1;
		tcphdr = (struct tcphdr*)&data[sizeof(struct ether_header) + iphdr->ip_hl * 4];
	} else {
		if (length < sizeof(struct ether_header) + sizeof(struct ip6_hdr))
			return (uintptr_t)-1;
		struct ip6_hdr* ipv6hdr = (struct ip6_hdr*)&data[sizeof(struct ether_header)];
		// TODO: parse and skip extension headers.
		if (ipv6hdr->ip6_nxt != IPPROTO_TCP)
			return (uintptr_t)-1;
		if (length < sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
			return (uintptr_t)-1;
		tcphdr = (struct tcphdr*)&data[sizeof(struct ether_header) + sizeof(struct ip6_hdr)];
	}

	struct tcp_resources* res = (struct tcp_resources*)a0;
	res->seq = htonl(ntohl(tcphdr->th_seq) + (uint32)a1);
	res->ack = htonl(ntohl(tcphdr->th_ack) + (uint32)a2);

	debug("extracted seq: %08x\n", res->seq);
	debug("extracted ack: %08x\n", res->ack);

	return 0;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NONE

#include <sys/resource.h>

static void sandbox_common()
{
#if !SYZ_THREADED
#if SYZ_EXECUTOR
	if (!flag_threaded)
#endif
		if (setsid() == -1)
			fail("setsid failed");
#endif

	// Some minimal sandboxing.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = 8 << 20;
	setrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 256; // see kMaxFd
	setrlimit(RLIMIT_NOFILE, &rlim);
}
#endif //  SYZ_EXECUTOR || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NONE

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE

static void loop();

static int do_sandbox_none(void)
{
	sandbox_common();
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun(procid);
#endif
	loop();
	return 0;
}
#endif // SYZ_EXECUTOR || SYZ_SANDBOX_NONE

#if SYZ_EXECUTOR || SYZ_SANDBOX_SETUID

#include <sys/wait.h>

static void loop();

static int wait_for_loop(int pid)
{
	if (pid < 0)
		fail("sandbox fork failed");
	debug("spawned loop pid %d\n", pid);
	int status = 0;
	while (waitpid(-1, &status, WUNTRACED) != pid) {
	}
	return WEXITSTATUS(status);
}

#define SYZ_HAVE_SANDBOX_SETUID 1
static int do_sandbox_setuid(void)
{
	int pid = fork();
	if (pid != 0)
		return wait_for_loop(pid);

	sandbox_common();
#if SYZ_EXECUTOR || SYZ_NET_INJECTION
	initialize_tun(procid);
#endif

	char pwbuf[1024];
	struct passwd *pw, pwres;
	if (getpwnam_r("nobody", &pwres, pwbuf, sizeof(pwbuf), &pw) != 0 || !pw)
		fail("getpwnam_r(\"nobody\") failed");

	if (setgroups(0, NULL))
		fail("failed to setgroups");
	if (setgid(pw->pw_gid))
		fail("failed to setgid");
	if (setuid(pw->pw_uid))
		fail("failed to setuid");

	loop();
	doexit(1);
}
#endif // SYZ_EXECUTOR || SYZ_SANDBOX_SETUID
