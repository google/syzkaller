// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bwrap

import (
	"bufio"
	"context"
	"encoding/binary"
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
)

const (
	handshakeTimeout = 30 * time.Second
	maxConnectLine   = 1024
)

var disallowedPrefixes = []netip.Prefix{
	// RFC 6598 shared address space (CGNAT).
	netip.MustParsePrefix("100.64.0.0/10"),
	// GCP Restricted and Private Google Access VIPs (restricted/private.googleapis.com).
	netip.MustParsePrefix("199.36.153.4/30"),
	netip.MustParsePrefix("199.36.153.8/30"),
	netip.MustParsePrefix("2600:2d00:2:1000::/64"),
	netip.MustParsePrefix("2600:2d00:2:2000::/64"),
}

type proxy struct {
	sockPath   string
	scriptPath string
	ln         net.Listener
	dial       func(ctx context.Context, hostPort string) (net.Conn, error)
}

var (
	proxyOnce    sync.Once
	defaultInst  *proxy
	defaultError error
)

// startDefaultProxy starts a process-wide Unix-socket proxy shared across sandboxed commands.
func startDefaultProxy(hasUser bool, uid, gid uint32) (*proxy, error) {
	proxyOnce.Do(func() {
		defaultInst, defaultError = initDefaultProxy(hasUser, uid, gid)
	})
	return defaultInst, defaultError
}

func initDefaultProxy(hasUser bool, uid, gid uint32) (p *proxy, err error) {
	dir, err := os.MkdirTemp("", "syzkaller-proxy-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if p != nil {
				p.Close()
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
	if hasUser {
		if err = os.Chown(p.sockPath, int(uid), int(gid)); err != nil {
			return nil, err
		}
	}
	return p, nil
}

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
	scriptPath := filepath.Join(dir, "git-proxy.sh")
	script := fmt.Sprintf(`#!/bin/sh
sock="/run/.syz_proxy.sock"
if [ ! -S "$sock" ]; then
	sock=%q
fi
(printf "CONNECT %%s:%%s\n" "$1" "$2"; exec cat) | exec socat - "UNIX-CONNECT:$sock"
`, sockPath)
	if err = os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return nil, err
	}
	p := &proxy{sockPath: sockPath, scriptPath: scriptPath, ln: ln, dial: dial}
	go p.serve()
	return p, nil
}

func (p *proxy) Close() error {
	return p.ln.Close()
}

func (p *proxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

func (p *proxy) handleConn(client net.Conn) {
	defer client.Close()
	// Bound the handshake phase; once proxying starts, the sandboxed command's own
	// timeout governs connection lifetime (e.g. long git clones).
	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))
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
	dialCtx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	targetConn, err := p.dial(dialCtx, hostPort)
	cancel()
	if err != nil {
		log.Logf(0, "bwrap proxy: blocked %s: %v", hostPort, err)
		if isSocks5 {
			// SOCKS5 reply 0x02: connection not allowed by ruleset.
			_, _ = client.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
		return
	}
	log.Logf(1, "bwrap proxy: allowed %s", hostPort)
	defer targetConn.Close()
	if isSocks5 {
		// SOCKS5 reply 0x00: succeeded.
		if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
	}
	_ = client.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	pipe := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	wg.Add(2)
	go pipe(targetConn, br)
	go pipe(client, targetConn)
	wg.Wait()
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
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
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
	dialer := net.Dialer{Timeout: handshakeTimeout}
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
