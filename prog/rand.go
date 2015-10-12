// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/sys"
)

type randGen struct {
	*rand.Rand
	createDepth int
}

func newRand(rs rand.Source) *randGen {
	return &randGen{rand.New(rs), 0}
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

func (r *randGen) randInt() uintptr {
	v := r.rand64()
	r.choose(
		100, func() { v %= 10 },
		10, func() { v %= 256 },
		10, func() { v %= 4 << 10 },
		10, func() { v %= 64 << 10 },
		1, func() { v %= 1 << 31 },
		1, func() {},
	)
	r.choose(
		10, func() {},
		1, func() { v = uintptr(-int(v)) },
	)
	return v
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
	if r.oneOf(5) && len(s.files) != 0 {
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

var sockFamilies = []uint16{AF_LOCAL, AF_INET, AF_INET6, AF_IPX, AF_NETLINK, AF_X25, AF_AX25, AF_ATMPVC, AF_APPLETALK, AF_PACKET}

func (r *randGen) sockaddr(s *state) []byte {
	fa := sockFamilies[r.Intn(len(sockFamilies))]
	port := 13269 + uint16(r.Intn(20))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, fa) // this is actually host byte order
	switch fa {
	case AF_LOCAL:
		buf.WriteString(r.filename(s))
	case AF_INET:
		binary.Write(buf, binary.BigEndian, port)
		binary.Write(buf, binary.BigEndian, uint32(127<<24+0<<16+0<<8+1))
	case AF_INET6:
		binary.Write(buf, binary.BigEndian, port)
		binary.Write(buf, binary.BigEndian, uint32(r.Int63())) // flow info
		binary.Write(buf, binary.BigEndian, uint64(0))         // addr: loopback
		binary.Write(buf, binary.BigEndian, uint64(1))         // addr: loopback
		binary.Write(buf, binary.BigEndian, uint32(r.Int63())) // scope id
	case AF_IPX:
	case AF_NETLINK:
	case AF_X25:
	case AF_AX25:
	case AF_ATMPVC:
	case AF_APPLETALK:
	case AF_PACKET:
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
		"posix_acl_access", "mime_type", "md5sum", "nodev", "self", "sysfs", "rootfs",
		"ramfs", "bdev", "proc", "cgroup", "cpuset", "tmpfs", "devtmpfs", "debugfs",
		"securityfs", "sockfs", "pipefs", "anon_inodefs", "devpts", "ext3", "ext2",
		"ext4", "hugetlbfs", "vfat", "ecryptfs", "fuseblk", "fuse", "fusectl", "pstore",
		"mqueue", "rpc_pipefs", "nfs", "nfs4", "nfsd", "binfmt_misc", "autofs", "xfs",
		"jfs", "msdos", "ntfs", "minix", "hfs", "hfsplus", "qnx4", "ufs", "btrfs"}
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
					constArg(CLOCK_REALTIME),
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
				constArg(PROT_READ | PROT_WRITE),
				constArg(MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED),
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
		1, func() {},
		1, func() { arg.AddrOffset = -int(size) },
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
	if r.createDepth > 2 {
		special := res.SpecialValues()
		return constArg(special[r.Intn(len(special))]), nil
	}
	r.createDepth++
	defer func() { r.createDepth-- }()

	sk := res.Subkind
	if r.oneOf(50) {
		// Spoof resource subkind.
		all := res.SubKinds()
		sk = all[r.Intn(len(all))]
	}
	// Find calls that produce the necessary resources.
	var metas []*sys.Call
	// Recurse into arguments to see if there is an out/inout arg of necessary type.
	var checkArg func(typ sys.Type, dir ArgDir) bool
	checkArg = func(typ sys.Type, dir ArgDir) bool {
		if resarg, ok := typ.(sys.ResourceType); ok && dir != DirIn && resarg.Kind == res.Kind &&
			(resarg.Subkind == sk || resarg.Subkind == sys.ResAny || sk == sys.ResAny) {
			return true
		}
		switch typ1 := typ.(type) {
		case sys.ArrayType:
			if checkArg(typ1.Type, dir) {
				return true
			}
		case sys.StructType:
			for _, fld := range typ1.Fields {
				if checkArg(fld, dir) {
					return true
				}
			}
		case sys.PtrType:
			if checkArg(typ1.Type, ArgDir(typ1.Dir)) {
				return true
			}
		}
		return false
	}
	for _, meta := range s.enabledCalls {
		ok := false
		for _, arg := range meta.Args {
			if checkArg(arg, DirIn) {
				ok = true
				break
			}
		}
		if !ok && meta.Ret != nil && checkArg(meta.Ret, DirOut) {
			ok = true
		}
		if ok {
			metas = append(metas, meta)
		}
	}
	if len(metas) == 0 {
		if len(s.enabledCalls) != len(sys.Calls) {
			// We used only a subset of all syscalls,
			// so we legitimately may not be able to create the resource.
			return constArg(res.Default()), nil
		}
		panic(fmt.Sprintf("can't create resource %v/%v", res.Kind, sk))
	}

	// Now we have a set of candidate calls that can create the necessary resource.
	for i := 0; i < 1e3; i++ {
		// Generate one of them.
		meta := metas[r.Intn(len(metas))]
		calls := r.generateParticularCall(s, meta)
		assignTypeAndDir(calls[len(calls)-1])
		s1 := newState(s.enabledCalls)
		s1.analyze(calls[len(calls)-1])
		// Now see if we have what we want.
		var allres []*Arg
		for sk1, ress := range s1.resources[res.Kind] {
			if sk1 == sys.ResAny || sk == sys.ResAny || sk1 == sk {
				allres = append(allres, ress...)
			}
		}
		if len(allres) != 0 {
			// Bingo!
			arg := resultArg(allres[r.Intn(len(allres))])
			return arg, calls
		}
		switch meta.Name {
		case "getgroups":
			// Returns groups in an array.
		default:
			panic(fmt.Sprintf("unexpected call failed to create a resource %v/%v: %v", res.Kind, sk, meta.Name))
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

func (r *randGen) generateCall(s *state) []*Call {
	meta := s.enabledCalls[r.rand(len(s.enabledCalls))]
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
	// Pass 2: fill in size arguments.
	for i, typ := range types {
		if a, ok := typ.(sys.LenType); ok {
			size := sizes[a.Buf]
			if size == nil {
				panic(fmt.Sprintf("no size for %v[%v] (%+v)", a.Name(), a.Buf, sizes))
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
		case sys.IntType, sys.FlagsType, sys.FileoffType, sys.ResourceType:
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
				if ress := s.resources[a.Kind]; ress != nil {
					allres := ress[a.Subkind]
					allres = append(allres, ress[sys.ResAny]...)
					if a.Subkind == sys.ResAny || r.oneOf(10) {
						for _, v := range ress {
							allres = append(allres, v...)
						}
					}
					if len(allres) != 0 {
						// TODO: negative PIDs mean process group,
						// we should be able to negate an existing PID.
						arg = resultArg(allres[r.Intn(len(allres))])
					}
				}
				if arg == nil {
					arg, calls = r.createResource(s, a)
				}
			},
			10, func() {
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
		case sys.BufferSockaddr:
			data := r.sockaddr(s)
			if dir == DirOut {
				return nil, constArg(uintptr(len(data))), nil
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
	case sys.IntType:
		v := r.randInt()
		if a.Limit != 0 && !r.oneOf(100) {
			v %= a.Limit
		}
		return constArg(v), nil, nil
	case sys.FilenameType:
		filename := r.filename(s)
		return dataArg([]byte(filename)), nil, nil
	case sys.ArrayType:
		count := r.rand(6)
		var inner []*Arg
		var calls []*Call
		for i := uintptr(0); i < count; i++ {
			arg1, _, calls1 := r.generateArg(s, a.Type, dir, nil)
			inner = append(inner, arg1)
			calls = append(calls, calls1...)
		}
		return groupArg(inner), constArg(count), calls
	case sys.StructType:
		if dir != DirOut && (a.Name() == "timespec" || a.Name() == "timeval") {
			usec := a.Name() == "timeval"
			arg, calls = r.timespec(s, usec)
			return arg, nil, calls
		}
		args, calls := r.generateArgs(s, a.Fields, dir)
		return groupArg(args), nil, calls
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
