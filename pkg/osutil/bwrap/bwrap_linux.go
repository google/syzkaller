// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package bwrap implements bubblewrap-based process sandboxing and filtered network proxying.
package bwrap

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	sandboxUsername  = "syzkaller"
	sandboxHome      = "/home/syzkaller"
	tmpfsSizeLarge   = int64(8) << 30 // 8 GiB (/tmp and HOME, e.g. for Bazel caches and build temporaries)
	tmpfsSizeDefault = 64 << 20       // 64 MiB
)

type sandboxCreds struct {
	uid uint32
	gid uint32
}

// Option configures a bwrap sandbox invocation.
type Option func(*config)

type config struct {
	netProxy    bool
	customProxy *proxy
	readOnly    []string
	readWrite   []string
	env         []string
}

func withCustomProxy(p *proxy) Option {
	return func(c *config) {
		c.netProxy = true
		c.customProxy = p
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

// WithEnv sets additional KEY=VALUE environment variables inside the sandbox.
func WithEnv(env ...string) Option {
	return func(c *config) {
		c.env = append(c.env, env...)
	}
}

// bwrapSystemMounts are host paths mounted read-only for standard build, VCS, and
// symbolization tools. Put target-specific toolchains in Target.ToolchainDirs instead.
var bwrapSystemMounts = []string{
	// Binaries, shared libraries, and packaged toolchains (e.g. /opt/git).
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/opt",
	"/etc/alternatives",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	// TLS roots and system-wide git config (e.g. safe.directory).
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/gitconfig",
	// DNS/NSS config and UID/GID tables (/etc/shadow is omitted; git, python, and id
	// fail if the current UID is missing from /etc/passwd).
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/group",
}

var (
	lookupUser = sync.OnceValues(func() (sandboxCreds, error) {
		u, err := user.Lookup(sandboxUsername)
		if err != nil {
			return sandboxCreds{}, fmt.Errorf("user %q is not found, can't sandbox command: %w", sandboxUsername, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return sandboxCreds{}, fmt.Errorf("invalid uid %q for %q: %w", u.Uid, sandboxUsername, err)
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return sandboxCreds{}, fmt.Errorf("invalid gid %q for %q: %w", u.Gid, sandboxUsername, err)
		}
		if uid == 0 || gid == 0 {
			return sandboxCreds{}, fmt.Errorf("user %q must not have uid/gid 0 (got %d:%d)",
				sandboxUsername, uid, gid)
		}
		return sandboxCreds{uid: uint32(uid), gid: uint32(gid)}, nil
	})
	lookupBwrap = sync.OnceValues(func() (string, error) {
		path, err := exec.LookPath("bwrap")
		if err != nil {
			return "", fmt.Errorf("bwrap not found: %w", err)
		}
		return path, nil
	})
	checkAvailable = sync.OnceValue(func() error {
		// Pass a nested /tmp path so Wrap also exercises --dir and --chmod from bwrapBindArgs,
		// catching old bwrap versions lacking any flag used by Wrap upfront.
		probeDir, err := os.MkdirTemp("/tmp", "syz-probe-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(probeDir)
		if err := os.Chmod(probeDir, 0755); err != nil {
			return err
		}
		nested := filepath.Join(probeDir, "d")
		if err := os.MkdirAll(nested, 0755); err != nil {
			return err
		}
		cmd := exec.Command("true")
		if err := Wrap(cmd, WithReadOnly(nested)); err != nil {
			return err
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("bwrap probe failed: %w (%s)", err, bytes.TrimSpace(out))
		}
		// Check socat upfront rather than failing on the first proxied git:// call.
		if _, err := exec.LookPath("socat"); err != nil {
			return fmt.Errorf("socat not found: %w", err)
		}
		return nil
	})
	bwrapBaseArgs = []string{
		"--unshare-all",
		"--unshare-user",
		"--disable-userns",
		"--die-with-parent",
		"--new-session",
		"--cap-drop", "ALL",
		"--clearenv",
	}
	bwrapForbiddenMounts = []string{
		"/proc",
		"/dev",
		"/sys",
		"/run",
		"/etc",
		"/boot",
		"/var/tmp",
	}
)

// SandboxUser returns the UID and GID of the unprivileged syzkaller sandbox user.
func SandboxUser() (uint32, uint32, error) {
	creds, err := lookupUser()
	return creds.uid, creds.gid, err
}

// Available verifies that the syzkaller user exists, bwrap and socat are installed,
// and bwrap can set up the namespaces and mounts used by Wrap.
func Available() error {
	return checkAvailable()
}

// Wrap wraps cmd in bwrap as the syzkaller sandbox user with a minimal read-only
// root filesystem, isolated namespaces, a scrubbed environment, and an optional
// filtered network proxy. cmd.Env must be empty; pass extra environment variables
// via WithEnv.
// If cmd.Dir is set, it is mounted read-only as the working directory (pass WithReadWrite(cmd.Dir)
// if it must be writable); if empty, the command runs in the sandbox's private /tmp tmpfs.
// The access mode of a path is determined by its closest mounted ancestor (or the path itself),
// irrespective of the order of options. If the same path is requested both read-only
// and read-write, it is mounted read-write.
func Wrap(cmd *exec.Cmd, opts ...Option) error {
	if len(cmd.Env) > 0 {
		return errors.New("bwrap: cmd.Env must not be set; use WithEnv")
	}
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	creds, err := lookupUser()
	if err != nil {
		return err
	}
	bwrapPath, err := lookupBwrap()
	if err != nil {
		return err
	}
	envArgs, err := bwrapEnvArgs(cfg.env)
	if err != nil {
		return err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: creds.uid,
		Gid: creds.gid,
	}
	origPath := cmd.Path
	origArgs := cmd.Args
	if len(origArgs) == 0 {
		origArgs = []string{origPath}
	}
	args := slices.Concat([]string{bwrapPath}, bwrapBaseArgs, envArgs)
	for _, p := range bwrapSystemMounts {
		args = append(args, "--ro-bind-try", p, p)
	}
	largeSize := strconv.FormatInt(tmpfsSizeLarge, 10)
	defSize := strconv.Itoa(tmpfsSizeDefault)
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--size", largeSize, "--tmpfs", "/tmp",
		"--size", defSize, "--tmpfs", "/var/tmp",
		"--size", defSize, "--tmpfs", "/run",
		"--size", defSize, "--tmpfs", "/dev/shm",
		"--size", largeSize, "--tmpfs", sandboxHome,
		"--setenv", "HOME", sandboxHome,
		"--setenv", "CCACHE_DISABLE", "1",
	)
	chdir, execPath, mountArgs, err := collectMounts(&cfg, cmd.Dir, origPath)
	if err != nil {
		return err
	}
	args = append(args, mountArgs...)
	args = append(args, "--chdir", chdir)

	if cfg.netProxy {
		p := cfg.customProxy
		if p == nil {
			p, err = startDefaultProxy()
			if err != nil {
				return err
			}
		}
		// "socks5h://localhost/<path>" is libcurl's syntax for a SOCKS5 proxy over a Unix
		// domain socket (used by git's HTTP/HTTPS transport and curl). Non-libcurl tools
		// generally do not understand this URL scheme, which is fine because the proxy is
		// intended for git (HTTP/HTTPS via libcurl, git:// via GIT_PROXY_COMMAND) while
		// other tools fail closed in the isolated network namespace.
		// Set both lowercase and uppercase proxy variables: libcurl ignores uppercase
		// HTTP_PROXY (to avoid CGI header collisions) and reads lowercase http_proxy,
		// https_proxy/HTTPS_PROXY, and ALL_PROXY, while setting all variants ensures any
		// pre-existing host proxy variables are overridden.
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
	args = append(args, "--", execPath)
	args = append(args, origArgs[1:]...)
	cmd.Path = bwrapPath
	cmd.Args = args
	// Clear cmd.Env so unallowed host variables (e.g. API keys) are not even
	// exposed in the outer bwrap process's /proc/1/environ inside the PID namespace.
	cmd.Env = []string{}
	// Bwrap sets the working directory inside the sandbox via --chdir.
	cmd.Dir = ""
	return nil
}

func bwrapEnvArgs(extra []string) ([]string, error) {
	var args []string
	for _, key := range []string{"PATH", "RUSTUP_HOME", "CARGO_HOME"} {
		if val, ok := os.LookupEnv(key); ok {
			args = append(args, "--setenv", key, val)
		}
	}
	for _, kv := range extra {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bwrap: invalid env entry %q", kv)
		}
		args = append(args, "--setenv", k, v)
	}
	return args, nil
}

type mountMapping struct {
	raw      string
	resolved string
}

// collectMounts resolves the working directory, explicit mounts, and executable path,
// returning the sandbox working directory, executable path, and bwrap mount arguments.
func collectMounts(cfg *config, cmdDir, origPath string) (string, string, []string, error) {
	// Key by symlink-resolved path so forbidden-mount checks cannot be bypassed via symlinks
	// and duplicate entries merge (with read-write taking precedence over read-only).
	mounts := make(map[string]bool)
	var mappings []mountMapping
	addMount := func(p string, writable bool) (string, error) {
		if p == "" {
			return "", nil
		}
		raw, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		resolved, err := resolvePath(raw)
		if err != nil {
			return "", err
		}
		mounts[resolved] = mounts[resolved] || writable
		mappings = append(mappings, mountMapping{raw: raw, resolved: resolved})
		if raw != resolved {
			mappings = append(mappings, mountMapping{raw: resolved, resolved: resolved})
		}
		return resolved, nil
	}
	// Default to the sandbox's private /tmp tmpfs; otherwise bind cmd.Dir read-only.
	chdir := "/tmp"
	if cmdDir != "" {
		workDir, err := addMount(cmdDir, false)
		if err != nil {
			return "", "", nil, err
		}
		chdir = workDir
	}
	for _, p := range cfg.readOnly {
		if _, err := addMount(p, false); err != nil {
			return "", "", nil, err
		}
	}
	for _, p := range cfg.readWrite {
		if _, err := addMount(p, true); err != nil {
			return "", "", nil, err
		}
	}
	execPath, err := resolveExecPath(origPath, mounts, mappings)
	if err != nil {
		return "", "", nil, err
	}
	mountArgs, err := bwrapMountArgs(mounts)
	if err != nil {
		return "", "", nil, err
	}
	return chdir, execPath, mountArgs, nil
}

// resolveExecPath rewrites or mounts origPath so it is reachable inside the sandbox without
// calling EvalSymlinks on paths inside mounted directories (e.g. an untrusted cmd.Dir).
func resolveExecPath(origPath string, mounts map[string]bool, mappings []mountMapping) (string, error) {
	if !filepath.IsAbs(origPath) || isUnderSystemMounts(origPath) {
		return origPath, nil
	}
	cleanOrig := filepath.Clean(origPath)
	slices.SortFunc(mappings, func(a, b mountMapping) int {
		if len(a.raw) != len(b.raw) {
			return len(b.raw) - len(a.raw)
		}
		return strings.Compare(a.raw, b.raw)
	})
	for _, m := range mappings {
		if cleanOrig == m.raw || strings.HasPrefix(cleanOrig, m.raw+"/") {
			return m.resolved + strings.TrimPrefix(cleanOrig, m.raw), nil
		}
	}
	// Standalone host binary (e.g. a Go test binary in /tmp): resolve and bind read-only.
	resolved, err := resolvePath(cleanOrig)
	if err != nil {
		return "", err
	}
	if _, ok := mounts[resolved]; !ok && !isUnderSystemMounts(resolved) &&
		!isUnderAny(resolved, slices.Collect(maps.Keys(mounts))) {
		mounts[resolved] = false
	}
	return resolved, nil
}

// resolvePath returns the absolute path of p with symlinks resolved.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
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
		if p == "/" || p == "/tmp" || p == sandboxHome || isUnderAny(p, bwrapForbiddenMounts) {
			return nil, fmt.Errorf("bwrap: refusing to mount %q", p)
		}
		flag := "--ro-bind"
		if mounts[p] {
			flag = "--bind"
		}
		args = append(args, bwrapBindArgs(flag, p, paths)...)
	}
	return args, nil
}

// bwrapBindArgs returns the bwrap arguments to bind p at the same path inside the sandbox.
// Because --tmpfs /tmp mounts a fresh writable tmpfs at /tmp, binding a path under /tmp/<parent>/...
// causes bwrap to create synthetic parent directories in /tmp. Setting those synthetic ancestors to
// 0555 after the bind mount guards against accidental relative writes (e.g. "../foo") silently landing
// in the ephemeral tmpfs instead of failing with EACCES (a malicious process can chmod synthetic tmpfs
// dirs back to 0755, which only affects its private ephemeral tmpfs, never the host). Ancestors that
// are themselves bound (or inside a bound directory) are skipped so real host dirs are never chmodded.
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
