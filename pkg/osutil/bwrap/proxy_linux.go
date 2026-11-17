// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bwrap

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"golang.org/x/sync/errgroup"
)

const (
	handshakeTimeout   = 30 * time.Second
	dialTimeout        = 10 * time.Second
	defaultIdleTimeout = 5 * time.Minute
	maxConnectLine     = 1024
	maxConcurrentConns = 64
)

var disallowedPrefixes = []netip.Prefix{
	// RFC 1122 "this host on this network".
	netip.MustParsePrefix("0.0.0.0/8"),
	// RFC 6598 shared address space (CGNAT).
	netip.MustParsePrefix("100.64.0.0/10"),
	// Azure WireServer / metadata endpoint.
	netip.MustParsePrefix("168.63.129.16/32"),
	// RFC 6890 IETF protocol assignments.
	netip.MustParsePrefix("192.0.0.0/24"),
	// RFC 5737 documentation (TEST-NET-1, TEST-NET-2, TEST-NET-3).
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	// RFC 7526 deprecated 6to4 relay anycast.
	netip.MustParsePrefix("192.88.99.0/24"),
	// RFC 2544 benchmarking.
	netip.MustParsePrefix("198.18.0.0/15"),
	// GCP Restricted and Private Google Access VIPs (restricted/private.googleapis.com).
	netip.MustParsePrefix("199.36.153.4/30"),
	netip.MustParsePrefix("199.36.153.8/30"),
	// RFC 1112 reserved for future use.
	netip.MustParsePrefix("240.0.0.0/4"),
	// RFC 4291 deprecated IPv4-compatible IPv6 addresses.
	netip.MustParsePrefix("::/96"),
	// RFC 6052 / RFC 8215 NAT64 prefixes.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	// RFC 4380 Teredo tunneling.
	netip.MustParsePrefix("2001::/32"),
	// RFC 3849 IPv6 documentation.
	netip.MustParsePrefix("2001:db8::/32"),
	// RFC 3056 6to4 tunneling.
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2600:2d00:2:1000::/64"),
	netip.MustParsePrefix("2600:2d00:2:2000::/64"),
	// RFC 3879 deprecated IPv6 site-local unicast.
	netip.MustParsePrefix("fec0::/10"),
}

type proxy struct {
	sockPath    string
	scriptPath  string
	ln          net.Listener
	cancel      context.CancelFunc
	done        chan struct{}
	idleTimeout time.Duration
	dial        func(ctx context.Context, hostPort string) (net.Conn, error)
}

// startDefaultProxy starts a process-wide Unix-socket proxy owned by the sandbox user.
var startDefaultProxy = sync.OnceValues(func() (p *proxy, err error) {
	creds, err := lookupUser()
	if err != nil {
		return nil, err
	}
	// Always use /tmp rather than $TMPDIR: Unix socket paths are limited to 108 bytes,
	// and a custom $TMPDIR may be 0700 owned by root (untraversable by syzkaller).
	dir, err := os.MkdirTemp("/tmp", "syzkaller-proxy-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if p != nil {
				_ = p.Close()
			}
			_ = os.RemoveAll(dir)
		}
	}()
	if err = os.Chmod(dir, 0755); err != nil {
		return nil, err
	}
	if p, err = newProxy(dir, dialProxy); err != nil {
		return nil, err
	}
	if err = os.Chown(p.sockPath, int(creds.uid), int(creds.gid)); err != nil {
		return nil, err
	}
	return p, nil
})

func newProxy(dir string, dial func(ctx context.Context, hostPort string) (net.Conn, error)) (_ *proxy, err error) {
	sockPath := filepath.Join(dir, "proxy.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ln.Close()
		}
	}()
	if err = os.Chmod(sockPath, 0600); err != nil {
		return nil, err
	}
	// Keep git-proxy.sh alongside proxy.sock for the proxy's lifetime (process-wide, or
	// removed by Close in tests): Wrap only prepares *exec.Cmd, so bwrap --ro-bind-data
	// via cmd.ExtraFiles would leak parent FDs.
	scriptPath := filepath.Join(dir, "git-proxy.sh")
	// Use socat as the top-level process with a dual address (SYSTEM:...!!STDOUT) rather than
	// a shell pipeline "(printf ...; exec cat) | exec socat ...": git's atexit handler waits
	// for GIT_PROXY_COMMAND to exit before closing its stdin pipe, so a standalone pipeline cat
	// would block in read(0) forever when the proxy rejects and closes the Unix socket early.
	script := fmt.Sprintf(`#!/bin/sh
sock="/run/.syz_proxy.sock"
if [ ! -S "$sock" ]; then
	sock=%q
fi
host="$1"
case "$host" in
	'['*']') ;;
	*:*) host="[$host]" ;;
esac
export SYZ_PROXY_HDR="CONNECT $host:$2"
exec socat 'SYSTEM:printenv SYZ_PROXY_HDR && exec cat!!STDOUT' "UNIX-CONNECT:$sock"
`, sockPath)
	if err = os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{
		sockPath:    sockPath,
		scriptPath:  scriptPath,
		ln:          ln,
		cancel:      cancel,
		done:        make(chan struct{}),
		idleTimeout: defaultIdleTimeout,
		dial:        dial,
	}
	go p.serve(ctx)
	return p, nil
}

func (p *proxy) Close() error {
	p.cancel()
	err := p.ln.Close()
	<-p.done
	_ = os.Remove(p.scriptPath)
	return err
}

func (p *proxy) serve(ctx context.Context) {
	defer close(p.done)
	var eg errgroup.Group
	eg.SetLimit(maxConcurrentConns)
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				break
			}
			log.Logf(1, "bwrap proxy: accept failed: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		eg.Go(func() error {
			p.handleConn(ctx, conn)
			return nil
		})
	}
	_ = eg.Wait()
}

func (p *proxy) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()
	stopClient := context.AfterFunc(ctx, func() {
		_ = client.Close()
	})
	defer stopClient()

	handshakeDeadline := time.Now().Add(handshakeTimeout)
	_ = client.SetDeadline(handshakeDeadline)
	br := bufio.NewReaderSize(client, maxConnectLine)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	isSocks5 := first[0] == 0x05
	var hostPort string
	if isSocks5 {
		if hostPort, err = readSocks5Request(client, br); err != nil {
			return
		}
	} else {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return
		}
		var ok bool
		if hostPort, ok = strings.CutPrefix(strings.TrimSpace(string(line)), "CONNECT "); !ok {
			return
		}
	}
	dialCtx, cancel := context.WithDeadline(ctx, handshakeDeadline)
	targetConn, err := p.dial(dialCtx, hostPort)
	cancel()
	if err != nil {
		log.Logf(1, "bwrap proxy: blocked %q: %v", hostPort, err)
		if isSocks5 {
			// SOCKS5 reply 0x02: connection not allowed by ruleset.
			_, _ = client.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
		return
	}
	log.Logf(1, "bwrap proxy: allowed %q", hostPort)
	defer targetConn.Close()
	stopTarget := context.AfterFunc(ctx, func() {
		_ = targetConn.Close()
	})
	defer stopTarget()

	if isSocks5 {
		// SOCKS5 reply 0x00: succeeded.
		if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
	}
	deadline := time.Now().Add(p.idleTimeout)
	_ = client.SetDeadline(time.Time{})
	_ = client.SetReadDeadline(deadline)
	_ = targetConn.SetReadDeadline(deadline)
	pipe := func(dst, src net.Conn, r io.Reader) error {
		_, _ = io.Copy(idleWriter{dst: dst, src: src, idle: p.idleTimeout}, r)
		// Close both ends on first EOF/error so a half-open peer cannot hold FDs open.
		_ = client.Close()
		_ = targetConn.Close()
		return nil
	}
	var eg errgroup.Group
	eg.Go(func() error {
		return pipe(targetConn, client, br)
	})
	_ = pipe(client, targetConn, targetConn)
	_ = eg.Wait()
}

type idleWriter struct {
	dst, src net.Conn
	idle     time.Duration
}

func (w idleWriter) Write(b []byte) (int, error) {
	_ = w.dst.SetWriteDeadline(time.Now().Add(w.idle))
	n, err := w.dst.Write(b)
	if n > 0 {
		deadline := time.Now().Add(w.idle)
		_ = w.dst.SetReadDeadline(deadline)
		_ = w.src.SetReadDeadline(deadline)
	}
	return n, err
}

func readSocks5Request(w io.Writer, r io.Reader) (string, error) {
	readN := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		return buf, err
	}
	greet, err := readN(2)
	if err != nil || greet[0] != 0x05 {
		return "", fmt.Errorf("invalid socks5 greeting")
	}
	methods, err := readN(int(greet[1]))
	if err != nil {
		return "", err
	}
	if !slices.Contains(methods, 0x00) {
		_, _ = w.Write([]byte{0x05, 0xff})
		return "", fmt.Errorf("unsupported socks5 auth methods")
	}
	if _, err := w.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}
	hdr, err := readN(4)
	if err != nil || hdr[0] != 0x05 || hdr[1] != 0x01 {
		return "", fmt.Errorf("unsupported socks5 command")
	}
	var host string
	switch hdr[3] {
	case 0x01, 0x04:
		ipLen := 4
		if hdr[3] == 0x04 {
			ipLen = 16
		}
		ip, err := readN(ipLen)
		if err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03:
		n, err := readN(1)
		if err != nil {
			return "", err
		}
		domain, err := readN(int(n[0]))
		if err != nil {
			return "", err
		}
		host = string(domain)
	default:
		return "", fmt.Errorf("unsupported socks5 address type %d", hdr[3])
	}
	portBuf, err := readN(2)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf)))), nil
}

func checkProxyAddress(ctx context.Context, hostPort string) ([]net.IP, string, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, "", fmt.Errorf("invalid proxy target %q: %w", hostPort, err)
	}
	if port, err := strconv.Atoi(portStr); err != nil || (port != 80 && port != 443 && port != 9418) {
		return nil, "", fmt.Errorf("disallowed proxy port %q", portStr)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, "", fmt.Errorf("failed to resolve %q: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if err := checkProxyIP(addr.IP); err != nil {
			return nil, "", err
		}
		ips = append(ips, addr.IP)
	}
	return ips, portStr, nil
}

func checkProxyIP(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("invalid proxy IP %v", ip)
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return fmt.Errorf("disallowed proxy IP %v", ip)
	}
	for _, prefix := range disallowedPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("disallowed proxy IP %v", ip)
		}
	}
	return nil
}

func dialProxy(ctx context.Context, hostPort string) (net.Conn, error) {
	ips, portStr, err := checkProxyAddress(ctx, hostPort)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), portStr))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
