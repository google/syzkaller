// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <vector>

// Connection represents a client TCP connection.
// It connects to the given addr:port and allows to send/receive
// flatbuffers-encoded messages.
class Connection
{
public:
	Connection(const char* addr, const char* port)
	    : fd_(Connect(addr, port))
	{
	}

	int FD() const
	{
		return fd_;
	}

	template <typename Msg>
	void Send(const Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		auto off = Raw::Pack(fbb_, &msg);
		fbb_.FinishSizePrefixed(off);
		auto data = fbb_.GetBufferSpan();
		Send(data.data(), data.size());
		fbb_.Reset();
	}

	template <typename Msg>
	void Recv(Msg& msg)
	{
		typedef typename Msg::TableType Raw;
		flatbuffers::uoffset_t size;
		Recv(&size, sizeof(size));
		recv_buf_.resize(size);
		Recv(recv_buf_.data(), size);
		auto raw = flatbuffers::GetRoot<Raw>(recv_buf_.data());
		raw->UnPackTo(&msg);
	}

	void Send(const void* data, size_t size)
	{
		for (size_t sent = 0; sent < size;) {
			ssize_t n = write(fd_, static_cast<const char*>(data) + sent, size - sent);
			if (n > 0) {
				sent += n;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to send rpc", "fd=%d want=%zu sent=%zu n=%zd", fd_, size, sent, n);
		}
	}

private:
	const int fd_;
	std::vector<char> recv_buf_;
	flatbuffers::FlatBufferBuilder fbb_;

	void Recv(void* data, size_t size)
	{
		for (size_t recv = 0; recv < size;) {
			ssize_t n = read(fd_, static_cast<char*>(data) + recv, size - recv);
			if (n > 0) {
				recv += n;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				sleep_ms(1);
				continue;
			}
			failmsg("failed to recv rpc", "fd=%d want=%zu sent=%zu n=%zd", fd_, size, recv, n);
		}
	}

	static int Connect(const char* addr, const char* ports)
	{
		int port = atoi(ports);
		if (port == 0)
			failmsg("failed to parse manager port", "port=%s", ports);
		if (!strcmp(addr, "stdin"))
			return STDIN_FILENO;
		sockaddr_in saddr4 = {};
		saddr4.sin_family = AF_INET;
		saddr4.sin_port = htons(port);
		if (inet_pton(AF_INET, addr, &saddr4.sin_addr))
			return Connect(&saddr4, &saddr4.sin_addr, port);
		sockaddr_in6 saddr6 = {};
		saddr6.sin6_family = AF_INET6;
		saddr6.sin6_port = htons(port);
		if (inet_pton(AF_INET6, addr, &saddr6.sin6_addr))
			return Connect(&saddr6, &saddr6.sin6_addr, port);
		auto* hostent = gethostbyname(addr);
		if (!hostent)
			failmsg("failed to resolve manager addr", "addr=%s h_errno=%d", addr, h_errno);
		for (char** addr = hostent->h_addr_list; *addr; addr++) {
			int fd;
			if (hostent->h_addrtype == AF_INET) {
				memcpy(&saddr4.sin_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr4.sin_addr)));
				fd = Connect(&saddr4, &saddr4.sin_addr, port);
			} else if (hostent->h_addrtype == AF_INET6) {
				memcpy(&saddr6.sin6_addr, *addr, std::min<size_t>(hostent->h_length, sizeof(saddr6.sin6_addr)));
				fd = Connect(&saddr6, &saddr6.sin6_addr, port);
			} else {
				failmsg("unknown socket family", "family=%d", hostent->h_addrtype);
			}
			if (fd != -1)
				return fd;
		}
		failmsg("can't connect to manager", "addr=%s:%s", addr, ports);
	}

	template <typename addr_t>
	static int Connect(addr_t* addr, void* ip, int port)
	{
		auto* saddr = reinterpret_cast<sockaddr*>(addr);
		int fd = socket(saddr->sa_family, SOCK_STREAM, IPPROTO_TCP);
		if (fd == -1)
			fail("failed to create socket");
		char str[128] = {};
		inet_ntop(saddr->sa_family, ip, str, sizeof(str));
		if (connect(fd, saddr, sizeof(*addr))) {
			printf("failed to connect to manager at %s:%d: %s\n", str, port, strerror(errno));
			close(fd);
			return -1;
		}
		return fd;
	}

	Connection(const Connection&) = delete;
	Connection& operator=(const Connection&) = delete;
};

// Select is a wrapper around select system call.
class Select
{
public:
	Select()
	{
		FD_ZERO(&rdset_);
	}

	void Arm(int fd)
	{
		FD_SET(fd, &rdset_);
		max_fd_ = std::max(max_fd_, fd);
	}

	bool Ready(int fd) const
	{
		return FD_ISSET(fd, &rdset_);
	}

	void Wait(int ms)
	{
		timespec timeout = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000 * 1000};
		if (pselect(max_fd_ + 1, &rdset_, nullptr, nullptr, &timeout, nullptr) < 0) {
			if (errno != EINTR && errno != EAGAIN)
				fail("pselect failed");
		}
	}

	static void Prepare(int fd)
	{
		if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK))
			fail("fcntl(O_NONBLOCK) failed");
	}

private:
	fd_set rdset_;
	int max_fd_ = -1;

	Select(const Select&) = delete;
	Select& operator=(const Select&) = delete;
};
