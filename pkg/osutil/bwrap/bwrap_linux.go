// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package bwrap implements bubblewrap-based process sandboxing and filtered network proxying.
package bwrap

import (
	"bytes"
	"fmt"
	"maps"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

const (
	sandboxHome      = "/home/syzkaller"
	tmpfsSizeTmp     = 1 << 30  // 1 GiB
	tmpfsSizeDefault = 64 << 20 // 64 MiB
)

// Option configures a bwrap sandbox invocation.
type Option func(*config)

type config struct {
	hasUser     bool
	uid         uint32
	gid         uint32
	netProxy    bool
	customProxy *proxy
	readOnly    []string
	readWrite   []string
}

func withCustomProxy(p *proxy) Option {
	return func(c *config) {
		c.netProxy = true
		c.customProxy = p
	}
}

// WithUser runs bwrap and its network proxy socket as (uid, gid).
func WithUser(uid, gid uint32) Option {
	return func(c *config) {
		c.hasUser = true
		c.uid = uid
		c.gid = gid
	}
}

// WithNetworkProxy enables outbound HTTP/HTTPS/git access via the filtered proxy.
func WithNetworkProxy() Option {
	return func(c *config) {
		c.netProxy = true
	}
}

// WithReadOnly mounts additional paths read-only inside the sandbox.
func WithReadOnly(paths ...string) Option {
	return func(c *config) {
		c.readOnly = append(c.readOnly, paths...)
	}
}

// WithReadWrite mounts additional paths read-write inside the sandbox.
func WithReadWrite(paths ...string) Option {
	return func(c *config) {
		c.readWrite = append(c.readWrite, paths...)
	}
}

var bwrapSystemMounts = []string{
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/opt",
	"/etc/alternatives",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/gitconfig",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/group",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
}

// Available verifies that bwrap and socat are installed and that bwrap can create
// unprivileged user/mount/PID/network namespaces as (uid, gid).
func Available(uid, gid uint32) error {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return fmt.Errorf("bwrap not found: %w", err)
	}
	cmd := exec.Command(bwrapPath,
		"--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent",
		"--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
		"--", "/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("bwrap probe failed: %w (%s)", err, bytes.TrimSpace(out))
	}
	if _, err := exec.LookPath("socat"); err != nil {
		return fmt.Errorf("socat not found: %w", err)
	}
	return nil
}

// Wrap wraps cmd in bwrap with a minimal read-only root filesystem, isolated namespaces,
// and an optional filtered network proxy.
// cmd.Dir must be set before calling Wrap, it is mounted read-write.
// The access mode of a path is determined by its closest mounted ancestor (or the path itself),
// irrespective of the order of options. If the same path is requested both read-only
// and read-write, it is mounted read-write.
func Wrap(cmd *exec.Cmd, opts ...Option) error {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return err
	}
	if cfg.hasUser {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = new(syscall.SysProcAttr)
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: cfg.uid,
			Gid: cfg.gid,
		}
	}
	origPath := cmd.Path
	origArgs := cmd.Args
	if len(origArgs) == 0 {
		origArgs = []string{origPath}
	}
	args := []string{
		bwrapPath,
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		"--die-with-parent",
	}
	for _, p := range bwrapSystemMounts {
		args = append(args, "--ro-bind-try", p, p)
	}
	tmpSize := strconv.Itoa(tmpfsSizeTmp)
	defSize := strconv.Itoa(tmpfsSizeDefault)
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--size", tmpSize, "--tmpfs", "/tmp",
		"--size", defSize, "--tmpfs", "/var/tmp",
		"--size", defSize, "--tmpfs", "/run",
		"--size", defSize, "--tmpfs", "/dev/shm",
		"--size", defSize, "--tmpfs", sandboxHome,
		"--setenv", "HOME", sandboxHome,
		"--setenv", "CCACHE_DISABLE", "1",
	)

	// Maps the host paths to mount to whether they must be writable.
	mounts := make(map[string]bool)
	addMount := func(p string, writable bool) {
		if p == "" {
			return
		}
		p = cleanAbs(p)
		mounts[p] = mounts[p] || writable
	}
	if filepath.IsAbs(origPath) && !isUnderSystemMounts(origPath) {
		addMount(origPath, false)
	}
	var workDir string
	if cmd.Dir != "" {
		workDir = cleanAbs(cmd.Dir)
	}
	if workDir != "" && workDir != "/" {
		addMount(workDir, true)
	}
	for _, p := range cfg.readOnly {
		addMount(p, false)
	}
	for _, p := range cfg.readWrite {
		addMount(p, true)
	}
	mountArgs, err := bwrapMountArgs(mounts)
	if err != nil {
		return err
	}
	args = append(args, mountArgs...)
	if workDir != "" && workDir != "/" {
		args = append(args, "--chdir", workDir)
	} else {
		args = append(args, "--chdir", "/tmp")
	}

	if cfg.netProxy {
		p := cfg.customProxy
		if p == nil {
			p, err = startDefaultProxy(cfg.hasUser, cfg.uid, cfg.gid)
			if err != nil {
				return err
			}
		}
		const (
			sandboxSock      = "/run/.syz_proxy.sock"
			sandboxGitScript = "/run/.syz_git_proxy"
			proxyURL         = "socks5h://localhost" + sandboxSock
		)
		args = append(args,
			"--ro-bind", p.sockPath, sandboxSock,
			"--ro-bind", p.scriptPath, sandboxGitScript,
			"--setenv", "ALL_PROXY", proxyURL,
			"--setenv", "http_proxy", proxyURL,
			"--setenv", "https_proxy", proxyURL,
			"--setenv", "HTTP_PROXY", proxyURL,
			"--setenv", "HTTPS_PROXY", proxyURL,
			"--setenv", "GIT_PROXY_COMMAND", sandboxGitScript,
		)
	}
	args = append(args, "--", origPath)
	args = append(args, origArgs[1:]...)
	cmd.Path = bwrapPath
	cmd.Args = args
	// Bwrap sets the working directory inside the sandbox via --chdir.
	cmd.Dir = ""
	return nil
}

func cleanAbs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// bwrapMountArgs returns the bwrap arguments that bind the given host paths at the same paths
// inside the sandbox. The map values tell whether the path must be writable.
// Bwrap applies binds in the order they are given, so a bind of a directory shadows
// all earlier binds of its descendants. Sorting the paths places every directory before
// its descendants, so that the most specific mount always determines the access mode.
func bwrapMountArgs(mounts map[string]bool) ([]string, error) {
	paths := slices.Sorted(maps.Keys(mounts))
	var args []string
	for _, p := range paths {
		if p == "/" {
			// It would shadow all the mounts that constitute the sandbox.
			return nil, fmt.Errorf("bwrap: refusing to mount the host root directory")
		}
		flag := "--ro-bind-try"
		if mounts[p] {
			flag = "--bind-try"
		}
		args = append(args, bwrapBindArgs(flag, p, paths)...)
	}
	return args, nil
}

// bwrapBindArgs returns the bwrap arguments to bind p at the same path inside the sandbox.
// Because --tmpfs /tmp mounts a fresh writable tmpfs at /tmp, binding a path under /tmp/<parent>/...
// causes bwrap to create synthetic parent directories in /tmp. We create those synthetic ancestors
// with 0755 before the bind mount and lock them to 0555 afterwards so the sandboxed process cannot
// create or modify sibling files in /tmp/<parent>. Ancestors that are themselves bound (or inside a
// bound directory) are skipped so we never chmod real host directories.
func bwrapBindArgs(flag, p string, boundPaths []string) []string {
	var tmpAncestors []string
	for cur := filepath.Dir(p); strings.HasPrefix(cur, "/tmp/"); cur = filepath.Dir(cur) {
		if isUnderAny(cur, boundPaths) {
			break
		}
		tmpAncestors = append(tmpAncestors, cur)
	}
	slices.Reverse(tmpAncestors)
	var args []string
	for _, anc := range tmpAncestors {
		args = append(args, "--dir", anc, "--chmod", "0755", anc)
	}
	args = append(args, flag, p, p)
	for _, anc := range slices.Backward(tmpAncestors) {
		args = append(args, "--chmod", "0555", anc)
	}
	return args
}

func isUnderAny(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func isUnderSystemMounts(p string) bool {
	return isUnderAny(filepath.Clean(p), bwrapSystemMounts)
}
