// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"

	"github.com/google/syzkaller/sys"
)

type randGen struct {
	*rand.Rand
	inCreateResource bool
}

func newRand(rs rand.Source) *randGen {
	return &randGen{rand.New(rs), false}
}

func (r *randGen) rand(n int) uintptr {
	return uintptr(r.Intn(n))
}

func (r *randGen) bin() bool {
	return r.Intn(2) == 0
}

func (r *randGen) oneOf(n int) bool {
	return r.Intn(n) == 0
}

func (r *randGen) rand64() uintptr {
	v := uintptr(r.Int63())
	if r.bin() {
		v |= 1 << 63
	}
	return v
}

// Some potentially interesting integers.
var specialInts = []uintptr{
	0, 1, 31, 32, 63, 64, 127, 128,
	129, 255, 256, 257, 511, 512,
	1023, 1024, 1025, 2047, 2048, 4095, 4096,
	(1 << 15) - 1, (1 << 15), (1 << 15) + 1,
	(1 << 16) - 1, (1 << 16), (1 << 16) + 1,
	(1 << 31) - 1, (1 << 31), (1 << 31) + 1,
	(1 << 32) - 1, (1 << 32), (1 << 32) + 1,
}

func (r *randGen) randInt() uintptr {
	v := r.rand64()
	r.choose(
		100, func() { v %= 10 },
		50, func() { v = specialInts[r.Intn(len(specialInts))] },
		10, func() { v %= 256 },
		10, func() { v %= 4 << 10 },
		10, func() { v %= 64 << 10 },
		1, func() { v %= 1 << 31 },
		1, func() {},
	)
	r.choose(
		100, func() {},
		5, func() { v = uintptr(-int(v)) },
		2, func() { v <<= uint(r.Intn(63)) },
	)
	return v
}

func (r *randGen) randRangeInt(begin int64, end int64) uintptr {
	if r.oneOf(100) {
		return r.randInt()
	}
	return uintptr(begin + r.Int63n(end-begin+1))
}

// biasedRand returns a random int in range [0..n),
// probability of n-1 is k times higher than probability of 0.
func (r *randGen) biasedRand(n, k int) int {
	nf, kf := float64(n), float64(k)
	rf := nf * (kf/2 + 1) * rand.Float64()
	bf := (-1 + math.Sqrt(1+2*kf*rf/nf)) * nf / kf
	return int(bf)
}

func (r *randGen) randBufLen() (n uintptr) {
	r.choose(
		1, func() { n = 0 },
		50, func() { n = r.rand(256) },
		5, func() { n = 4 << 10 },
	)
	return
}

func (r *randGen) randPageCount() (n uintptr) {
	r.choose(
		100, func() { n = r.rand(4) + 1 },
		5, func() { n = r.rand(20) + 1 },
		1, func() { n = (r.rand(3) + 1) * 1024 },
	)
	return
}

func (r *randGen) flags(vv []uintptr) uintptr {
	var v uintptr
	r.choose(
		10, func() { v = 0 },
		10, func() { v = vv[r.rand(len(vv))] },
		90, func() {
			for stop := false; !stop; stop = r.bin() {
				v |= vv[r.rand(len(vv))]
			}
		},
		1, func() { v = r.rand64() },
	)
	return v
}

func (r *randGen) filename(s *state) string {
	// TODO: support procfs and sysfs
	dir := "."
	if r.oneOf(2) && len(s.files) != 0 {
		files := make([]string, 0, len(s.files))
		for f := range s.files {
			files = append(files, f)
		}
		dir = files[r.Intn(len(files))]
		if len(dir) > 0 && dir[len(dir)-1] == 0 {
			dir = dir[:len(dir)-1]
		}
	}
	if len(s.files) == 0 || r.oneOf(10) {
		// Generate a new name.
		if r.bin() {
			special := []string{
				"control", // kdbus control file
				"bus",     // kdbus main bus
			}
			f := fmt.Sprintf("%v/%v\x00", dir, special[r.Intn(len(special))])
			if !s.files[f] {
				return f
			}
		}
		for i := 0; ; i++ {
			f := fmt.Sprintf("%v/file%v\x00", dir, i)
			if !s.files[f] {
				return f
			}
		}
	}
	files := make([]string, 0, len(s.files))
	for f := range s.files {
		files = append(files, f)
	}
	return files[r.Intn(len(files))]
}

var sockFamilies = []uint16{
	sys.AF_UNIX,
	sys.AF_INET,
	sys.AF_INET6,
	sys.AF_IPX,
	sys.AF_NETLINK,
	sys.AF_X25,
	sys.AF_AX25,
	sys.AF_ATMPVC,
	sys.AF_APPLETALK,
	sys.AF_PACKET,
}

func (r *randGen) inaddr(s *state) uint32 {
	// TODO: extract addresses of network interfaces.
	var addr uint32
	r.choose(
		// Note: assuming little-endian host
		5, func() { addr = 127<<0 + 0<<8 + 0<<16 + 1<<24 },
		3, func() { addr = 0 }, // INADDR_ANY
		1, func() { addr = ^uint32(0) }, // INADDR_NONE/INADDR_BROADCAST
	)
	return addr
}

func (r *randGen) inport(s *state) uint16 {
	return uint16(r.Intn(20))<<8 + 0xab
}

func (r *randGen) in6addr(s *state) (arg *Arg, calls []*Call) {
	// addr: loopback (big endian)
	return groupArg([]*Arg{
		constArg(0),
		constArg(0),
		constArg(0),
		constArg(1 << 24),
	}), nil
}

func (r *randGen) inaddrany(s *state) (arg *Arg, calls []*Call) {
	if r.bin() {
		return r.in6addr(s)
	} else {
		return groupArg([]*Arg{
			constArg(uintptr(r.inaddr(s))),
			constArg(0),
			constArg(0),
			constArg(0),
		}), nil
	}
}

func (r *randGen) sockaddr(s *state) []byte {
	fa := sockFamilies[r.Intn(len(sockFamilies))]
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, fa) // this is actually host byte order
	switch fa {
	case sys.AF_UNIX:
		buf.WriteString(r.filename(s))
	case sys.AF_INET:
		binary.Write(buf, binary.LittleEndian, r.inport(s))
		binary.Write(buf, binary.LittleEndian, r.inaddr(s))
	case sys.AF_INET6:
		binary.Write(buf, binary.LittleEndian, r.inport(s))
		binary.Write(buf, binary.BigEndian, uint32(r.Int63())) // flow info
		binary.Write(buf, binary.BigEndian, uint64(0))         // addr: loopback
		binary.Write(buf, binary.BigEndian, uint64(1))         // addr: loopback
		binary.Write(buf, binary.BigEndian, uint32(r.Int63())) // scope id
	case sys.AF_IPX:
	case sys.AF_NETLINK:
	case sys.AF_X25:
	case sys.AF_AX25:
	case sys.AF_ATMPVC:
	case sys.AF_APPLETALK:
	case sys.AF_PACKET:
		binary.Write(buf, binary.BigEndian, uint16(0)) // Physical-layer protocol
		binary.Write(buf, binary.BigEndian, uint32(0)) // Interface number
		binary.Write(buf, binary.BigEndian, uint16(0)) // ARP hardware type
		binary.Write(buf, binary.BigEndian, uint8(0))  // Packet type
		binary.Write(buf, binary.BigEndian, uint8(0))  // Length of address
		binary.Write(buf, binary.BigEndian, uint64(0)) // Physical-layer address
	default:
		panic("unknown socket domain")
	}
	if r.oneOf(2) {
		buf.Write(make([]byte, 128-len(buf.Bytes())))
	}
	data := buf.Bytes()
	if r.oneOf(100) {
		data = data[:r.Intn(len(data))]
	}
	return data
}

func (r *randGen) randString(s *state) []byte {
	if len(s.strings) != 0 && r.bin() {
		// Return an existing string.
		strings := make([]string, 0, len(s.strings))
		for s := range s.strings {
			strings = append(strings, s)
		}
		return []byte(strings[r.Intn(len(strings))])
	}
	dict := []string{"user", "keyring", "trusted", "system", "security", "selinux",
		"posix_acl_access", "mime_type", "md5sum", "nodev", "self",
		"bdev", "proc", "cgroup", "cpuset",
		"lo", "eth0", "eth1", "em0", "em1", "wlan0", "wlan1", "ppp0", "ppp1",
		"vboxnet0", "vboxnet1", "vmnet0", "vmnet1", "GPL"}
	punct := []byte{'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '+', '\\',
		'/', ':', '.', ',', '-', '\'', '[', ']', '{', '}'}
	buf := new(bytes.Buffer)
	for !r.oneOf(4) {
		r.choose(
			10, func() { buf.WriteString(dict[r.Intn(len(dict))]) },
			10, func() { buf.Write([]byte{punct[r.Intn(len(punct))]}) },
			1, func() { buf.Write([]byte{byte(r.Intn(256))}) },
		)
	}
	if !r.oneOf(100) {
		buf.Write([]byte{0})
	}
	return buf.Bytes()
}

func (r *randGen) filesystem(s *state) []byte {
	dict := []string{"sysfs", "rootfs", "ramfs", "tmpfs", "devtmpfs", "debugfs",
		"securityfs", "sockfs", "pipefs", "anon_inodefs", "devpts", "ext3", "ext2", "ext4",
		"hugetlbfs", "vfat", "ecryptfs", "kdbusfs", "fuseblk", "fuse", "rpc_pipefs",
		"nfs", "nfs4", "nfsd", "binfmt_misc", "autofs", "xfs", "jfs", "msdos", "ntfs",
		"minix", "hfs", "hfsplus", "qnx4", "ufs", "btrfs", "configfs", "ncpfs", "qnx6",
		"exofs", "befs", "vxfs", "gfs2", "gfs2meta", "fusectl", "bfs", "nsfs", "efs",
		"cifs", "efivarfs", "affs", "tracefs", "bdev", "ocfs2", "ocfs2_dlmfs", "hpfs",
		"proc", "afs", "reiserfs", "jffs2", "romfs", "aio", "sysv", "v7", "udf",
		"ceph", "pstore", "adfs", "9p", "hostfs", "squashfs", "cramfs", "iso9660",
		"coda", "nilfs2", "logfs", "overlay", "f2fs", "omfs", "ubifs", "openpromfs"}
	return []byte(dict[r.Intn(len(dict))] + "\x00")
}

func (r *randGen) algType(s *state) []byte {
	dict := []string{"aead", "hash", "rng", "skcipher"}
	res := make([]byte, 14)
	copy(res, dict[r.Intn(len(dict))])
	return res
}

func (r *randGen) algName(s *state) []byte {
	dict := []string{"cmac(aes)", "ecb(aes)", "cbc(aes)", "hmac(sha1)", "pcbc(fcrypt)", "ghash",
		"jitterentropy_rng", "stdrng", "stdrng", "stdrng", "stdrng", "hmac(sha256)", "stdrng",
		"stdrng", "stdrng", "stdrng", "stdrng", "842", "lz4hc", "lz4", "lzo", "crct10dif", "crc32",
		"crc32c", "michael_mic", "zlib", "deflate", "poly1305", "chacha20", "salsa20", "seed",
		"anubis", "khazad", "xeta", "xtea", "tea", "ecb(arc4)", "arc4", "cast6", "cast5", "camellia",
		"aes", "tnepres", "serpent", "twofish", "blowfish", "fcrypt", "des3_ede", "des", "tgr128",
		"tgr160", "tgr192", "wp256", "wp384", "wp512", "sha384", "sha512", "sha224", "sha256",
		"sha1", "rmd320", "rmd256", "rmd160", "rmd128", "md5", "md4", "digest_null", "compress_null",
		"ecb(cipher_null)", "cipher_null", "rsa", "poly1305", "xts(serpent)", "lrw(serpent)",
		"ctr(serpent)", "cbc(serpent)", "__ecb-serpent-sse2", "ecb(serpent)", "__xts-serpent-sse2",
		"__lrw-serpent-sse2", "__ctr-serpent-sse2", "__cbc-serpent-sse2", "__ecb-serpent-sse2",
		"salsa20", "xts(twofish)", "lrw(twofish)", "ctr(twofish)", "cbc(twofish)", "ecb(twofish)",
		"twofish", "ctr(blowfish)", "cbc(blowfish)", "ecb(blowfish)", "blowfish", "xts(camellia)",
		"lrw(camellia)", "ctr(camellia)", "cbc(camellia)", "ecb(camellia)", "camellia", "ctr(des3_ede)",
		"cbc(des3_ede)", "ecb(des3_ede)", "des3_ede", "aes"}
	res := make([]byte, 64)
	copy(res, dict[r.Intn(len(dict))])
	return res
}

func isSpecialStruct(typ sys.Type) func(r *randGen, s *state) (*Arg, []*Call) {
	if _, ok := typ.(sys.StructType); !ok {
		panic("must be a struct")
	}
	switch typ.Name() {
	case "timespec":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.timespec(s, false)
		}
	case "timeval":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.timespec(s, true)
		}
	case "in6_addr":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.in6addr(s)
		}
	case "in_addr_any":
		return func(r *randGen, s *state) (*Arg, []*Call) {
			return r.inaddrany(s)
		}
	}
	return nil
}

func (r *randGen) timespec(s *state, usec bool) (arg *Arg, calls []*Call) {
	// We need to generate timespec/timeval that are either (1) definitely in the past,
	// or (2) definitely in unreachable fututre, or (3) few ms ahead of now.
	// Note timespec/timeval can be absolute or relative to now.
	r.choose(
		1, func() {
			// now for relative, past for absolute
			arg = groupArg([]*Arg{constArg(0), constArg(0)})
		},
		1, func() {
			// few ms ahead for relative, past for absolute
			nsec := uintptr(10 * 1e6)
			if usec {
				nsec /= 1e3
			}
			arg = groupArg([]*Arg{constArg(0), constArg(nsec)})
		},
		1, func() {
			// unreachable fututre for both relative and absolute
			arg = groupArg([]*Arg{constArg(2e9), constArg(0)})
		},
		1, func() {
			// few ms ahead for absolute
			tp := groupArg([]*Arg{constArg(0), constArg(0)})
			var tpaddr *Arg
			tpaddr, calls = r.addr(s, 2*ptrSize, tp)
			gettime := &Call{
				Meta: sys.CallMap["clock_gettime"],
				Args: []*Arg{
					constArg(sys.CLOCK_REALTIME),
					tpaddr,
				},
			}
			calls = append(calls, gettime)
			sec := resultArg(tp.Inner[0])
			nsec := resultArg(tp.Inner[1])
			if usec {
				nsec.OpDiv = 1e3
				nsec.OpAdd = 10 * 1e3
			} else {
				nsec.OpAdd = 10 * 1e6
			}
			arg = groupArg([]*Arg{sec, nsec})
		},
	)
	return
}

func (r *randGen) addr1(s *state, size uintptr, data *Arg) (*Arg, []*Call) {
	npages := (size + pageSize - 1) / pageSize
	if r.oneOf(10) {
		return r.randPageAddr(s, npages, data), nil
	}
	for i := uintptr(0); i < maxPages-npages; i++ {
		free := true
		for j := uintptr(0); j < npages; j++ {
			if s.pages[i+j] {
				free = false
				break
			}
		}
		if !free {
			continue
		}
		c := &Call{
			Meta: sys.CallMap["mmap"],
			Args: []*Arg{
				pointerArg(i, 0, nil),
				pageSizeArg(npages, 0),
				constArg(sys.PROT_READ | sys.PROT_WRITE),
				constArg(sys.MAP_ANONYMOUS | sys.MAP_PRIVATE | sys.MAP_FIXED),
				constArg(sys.InvalidFD),
				constArg(0),
			},
		}
		return pointerArg(i, 0, data), []*Call{c}
	}
	return r.randPageAddr(s, npages, data), nil
}

func (r *randGen) addr(s *state, size uintptr, data *Arg) (*Arg, []*Call) {
	arg, calls := r.addr1(s, size, data)
	if arg.Kind != ArgPointer {
		panic("bad")
	}
	// Patch offset of the address.
	r.choose(
		50, func() {},
		50, func() { arg.AddrOffset = -int(size) },
		1, func() {
			if size > 0 {
				arg.AddrOffset = -r.Intn(int(size))
			}
		},
		1, func() { arg.AddrOffset = r.Intn(pageSize) },
	)
	return arg, calls
}

func (r *randGen) randPageAddr(s *state, npages uintptr, data *Arg) *Arg {
	var starts []uintptr
	for i := uintptr(0); i < maxPages-npages; i++ {
		busy := true
		for j := uintptr(0); j < npages; j++ {
			if !s.pages[i+j] {
				busy = false
				break
			}
		}
		// TODO: it does not need to be completely busy,
		// for example, mmap addr arg can be new memory.
		if !busy {
			continue
		}
		starts = append(starts, i)
	}
	if len(starts) != 0 {
		return pointerArg(starts[r.rand(len(starts))], 0, data)
	} else {
		return pointerArg(r.rand(int(maxPages-npages)), 0, data)
	}
}

func (r *randGen) createResource(s *state, res sys.ResourceType) (arg *Arg, calls []*Call) {
	if r.inCreateResource {
		special := res.SpecialValues()
		return constArg(special[r.Intn(len(special))]), nil
	}
	r.inCreateResource = true
	defer func() { r.inCreateResource = false }()

	kind := res.Desc.Name
	if r.oneOf(100) {
		// Spoof resource subkind.
		var all []string
		for kind1 := range sys.Resources {
			if sys.IsCompatibleResource(res.Desc.Kind[0], kind1) {
				all = append(all, kind1)
			}
		}
		kind = all[r.Intn(len(all))]
	}
	// Find calls that produce the necessary resources.
	metas0 := sys.ResourceConstructors(kind)
	// TODO: reduce priority of less specialized ctors.
	var metas []*sys.Call
	for _, meta := range metas0 {
		if s.ct == nil || s.ct.run[meta.ID] == nil {
			continue
		}
		metas = append(metas, meta)
	}
	if len(metas) == 0 {
		return constArg(res.Default()), nil
	}

	// Now we have a set of candidate calls that can create the necessary resource.
	for i := 0; i < 1e3; i++ {
		// Generate one of them.
		meta := metas[r.Intn(len(metas))]
		calls := r.generateParticularCall(s, meta)
		s1 := newState(s.ct)
		s1.analyze(calls[len(calls)-1])
		// Now see if we have what we want.
		var allres []*Arg
		for kind1, res1 := range s1.resources {
			if sys.IsCompatibleResource(kind, kind1) {
				allres = append(allres, res1...)
			}
		}
		if len(allres) != 0 {
			// Bingo!
			arg := resultArg(allres[r.Intn(len(allres))])
			return arg, calls
		}
		switch meta.Name {
		// Return resources in a variable-length array (length can be 0).
		case "getgroups", "ioctl$DRM_IOCTL_RES_CTX":
		default:
			panic(fmt.Sprintf("unexpected call failed to create a resource %v: %v", kind, meta.Name))
		}
		// Discard unsuccessful calls.
		for _, c := range calls {
			foreachArg(c, func(arg, _ *Arg, _ *[]*Arg) {
				if arg.Kind == ArgResult {
					delete(arg.Res.Uses, arg)
				}
			})
		}
	}
	// Generally we can loop several times, e.g. when we choose a call that returns
	// the resource in an array, but then generateArg generated that array of zero length.
	// But we must succeed eventually.
	panic("failed to create a resource")
}

func (r *randGen) choose(args ...interface{}) {
	if len(args) == 0 || len(args)%2 != 0 {
		panic("bad number of args to choose")
	}
	n := len(args) / 2
	weights := make([]int, n)
	funcs := make([]func(), n)
	total := 0
	for i := 0; i < n; i++ {
		weights[i] = total + args[i*2].(int)
		funcs[i] = args[i*2+1].(func())
		total = weights[i]
	}
	x := r.Intn(total)
	for i, w := range weights {
		if x < w {
			funcs[i]()
			return
		}
	}
	panic("choose is broken")
}

func (r *randGen) generateCall(s *state, p *Prog) []*Call {
	call := -1
	if len(p.Calls) != 0 {
		for i := 0; i < 5; i++ {
			c := p.Calls[r.Intn(len(p.Calls))].Meta
			call = c.ID
			// There is roughly half of mmap's so ignore them.
			if c.Name != "mmap" {
				break
			}
		}
	}
	meta := sys.Calls[s.ct.Choose(r.Rand, call)]
	return r.generateParticularCall(s, meta)
}

func (r *randGen) generateParticularCall(s *state, meta *sys.Call) (calls []*Call) {
	c := &Call{Meta: meta}
	c.Args, calls = r.generateArgs(s, meta.Args, DirIn)
	calls = append(calls, c)
	for _, c1 := range calls {
		assignTypeAndDir(c1)
		sanitizeCall(c1)
	}
	return calls
}

func (r *randGen) generateArgs(s *state, types []sys.Type, dir ArgDir) ([]*Arg, []*Call) {
	var calls []*Call
	args := make([]*Arg, len(types))
	sizes := make(map[string]*Arg)
	// Pass 1: generate all args except size arguments.
	for i, typ := range types {
		if _, ok := typ.(sys.LenType); ok {
			continue
		}
		arg, size, calls1 := r.generateArg(s, typ, dir, sizes)
		args[i] = arg
		calls = append(calls, calls1...)
		if size != nil {
			sizes[typ.Name()] = size
		}
	}

	// Pass 2: calculate size of the whole struct.
	// Now we know sizes of all non-size arguments and size arguments are const-size.
	var parentSize uintptr
	for i, typ := range types {
		parentSize += args[i].Size(typ)
	}
	if sizes["parent"] != nil {
		panic("parent is reserved len name")
	}
	sizes["parent"] = constArg(parentSize)

	// Pass 3: fill in size arguments.
	for i, typ := range types {
		if a, ok := typ.(sys.LenType); ok {
			size := sizes[a.Buf]
			if size == nil {
				panic(fmt.Sprintf("no size for %v[%v] (%+v), types: %+v", a.Name(), a.Buf, sizes, types))
			}
			if a.ByteSize {
				if size.Val != 0 && size.ByteSize == 0 {
					panic(fmt.Sprintf("no byte size for %v: size=%v", a.Name(), size.Val))
				}
				size = constArg(size.ByteSize)
			}
			args[i] = size
		}
	}
	return args, calls
}

func (r *randGen) generateArg(s *state, typ sys.Type, dir ArgDir, sizes map[string]*Arg) (arg, size *Arg, calls []*Call) {
	if dir == DirOut {
		// No need to generate something interesting for output scalar arguments.
		// But we still need to generate the argument itself so that it can be referenced
		// in subsequent calls. For the same reason we do generate pointer/array/struct
		// output arguments (their elements can be referenced in subsequent calls).
		switch typ.(type) {
		case sys.IntType, sys.FlagsType, sys.ConstType, sys.StrConstType, sys.FileoffType, sys.ResourceType:
			return constArg(0), nil, nil
		}
	}

	if typ.Optional() && r.oneOf(10) {
		if _, ok := typ.(sys.BufferType); ok {
			panic("impossible") // parent PtrType must be Optional instead
		}
		return constArg(typ.Default()), constArg(0), nil
	}

	switch a := typ.(type) {
	case sys.ResourceType:
		r.choose(
			1, func() {
				special := a.SpecialValues()
				arg = constArg(special[r.Intn(len(special))])
			},
			90, func() {
				// Get an existing resource.
				var allres []*Arg
				for name1, res1 := range s.resources {
					if sys.IsCompatibleResource(a.Desc.Name, name1) ||
						r.oneOf(20) && sys.IsCompatibleResource(a.Desc.Kind[0], name1) {
						allres = append(allres, res1...)
					}
				}
				if len(allres) != 0 {
					arg = resultArg(allres[r.Intn(len(allres))])
				} else {
					arg, calls = r.createResource(s, a)
				}
			},
			5, func() {
				// Create a new resource.
				arg, calls = r.createResource(s, a)
			},
		)
		return arg, nil, calls
	case sys.FileoffType:
		// TODO: can do better
		var arg *Arg
		r.choose(
			90, func() { arg = constArg(0) },
			10, func() { arg = constArg(r.rand(100)) },
			1, func() { arg = constArg(r.randInt()) },
		)
		return arg, nil, nil
	case sys.BufferType:
		switch a.Kind {
		case sys.BufferBlob:
			sz := r.randBufLen()
			if dir == DirOut {
				return nil, constArg(sz), nil
			}
			data := make([]byte, sz)
			for i := range data {
				data[i] = byte(r.Intn(256))
			}
			return dataArg(data), constArg(sz), nil
		case sys.BufferString:
			data := r.randString(s)
			return dataArg(data), constArg(uintptr(len(data))), nil
		case sys.BufferFilesystem:
			data := r.filesystem(s)
			return dataArg(data), constArg(uintptr(len(data))), nil
		case sys.BufferSockaddr:
			data := r.sockaddr(s)
			if dir == DirOut {
				return nil, constArg(uintptr(len(data))), nil
			}
			return dataArg(data), constArg(uintptr(len(data))), nil
		case sys.BufferAlgType:
			data := r.algType(s)
			if dir == DirOut {
				for i := range data {
					data[i] = 0
				}
			}
			return dataArg(data), constArg(uintptr(len(data))), nil
		case sys.BufferAlgName:
			data := r.algName(s)
			if dir == DirOut {
				for i := range data {
					data[i] = 0
				}
			}
			return dataArg(data), constArg(uintptr(len(data))), nil
		default:
			panic("unknown buffer kind")
		}
	case sys.VmaType:
		npages := r.randPageCount()
		arg := r.randPageAddr(s, npages, nil)
		return arg, pageSizeArg(npages, 0), nil
	case sys.FlagsType:
		return constArg(r.flags(a.Vals)), nil, nil
	case sys.ConstType:
		return constArg(a.Val), nil, nil
	case sys.StrConstType:
		return dataArg([]byte(a.Val)), constArg(uintptr(len(a.Val))), nil
	case sys.IntType:
		v := r.randInt()
		switch a.Kind {
		case sys.IntSignalno:
			v %= 130
		case sys.IntInaddr:
			v = uintptr(r.inaddr(s))
		case sys.IntInport:
			v = uintptr(r.inport(s))
		case sys.IntRange:
			v = r.randRangeInt(a.RangeBegin, a.RangeEnd)
		}
		return constArg(v), nil, nil
	case sys.FilenameType:
		filename := r.filename(s)
		return dataArg([]byte(filename)), nil, nil
	case sys.ArrayType:
		count := a.Len
		if count == 0 {
			count = r.rand(6)
		}
		sz := constArg(count)
		var inner []*Arg
		var calls []*Call
		for i := uintptr(0); i < count; i++ {
			arg1, _, calls1 := r.generateArg(s, a.Type, dir, nil)
			inner = append(inner, arg1)
			calls = append(calls, calls1...)
			sz.ByteSize += arg1.Size(a.Type)
		}
		return groupArg(inner), sz, calls
	case sys.StructType:
		if ctor := isSpecialStruct(a); ctor != nil && dir != DirOut {
			arg, calls = ctor(r, s)
			return
		}
		args, calls := r.generateArgs(s, a.Fields, dir)
		return groupArg(args), nil, calls
	case sys.UnionType:
		optType := a.Options[r.Intn(len(a.Options))]
		opt, size, calls := r.generateArg(s, optType, dir, sizes)
		return unionArg(opt, optType), size, calls
	case sys.PtrType:
		inner, size, calls := r.generateArg(s, a.Type, ArgDir(a.Dir), sizes)
		if ArgDir(a.Dir) == DirOut && inner == nil {
			// No data, but we should have got size.
			arg, calls1 := r.addr(s, size.Val, nil)
			calls = append(calls, calls1...)
			return arg, size, calls
		}
		if size == nil {
			size = constArg(inner.Size(a.Type))
		}
		if a.Type.Name() == "iocb" && len(s.resources["iocbptr"]) != 0 {
			// It is weird, but these are actually identified by kernel by address.
			// So try to reuse a previously used address.
			addrs := s.resources["iocbptr"]
			addr := addrs[r.Intn(len(addrs))]
			arg = pointerArg(addr.AddrPage, addr.AddrOffset, inner)
			return arg, size, calls
		}
		arg, calls1 := r.addr(s, inner.Size(a.Type), inner)
		calls = append(calls, calls1...)
		return arg, size, calls
	case sys.LenType:
		if sizes == nil || sizes[a.Buf] == nil {
			fmt.Printf("name=%v buf=%v sizes=%+v\n", a.Name(), a.Buf, sizes)
			panic("me no generate len")
		}
		return sizes[a.Name()], nil, nil
	default:
		panic("unknown argument type")
	}
}
