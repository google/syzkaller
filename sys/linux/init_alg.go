// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"math/rand"

	"github.com/google/syzkaller/prog"
)

func (arch *arch) generateSockaddrAlg(g *prog.Gen, typ0 prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	family := g.GenerateArg(typ.Fields[0], &calls)
	// There is very little point in generating feat/mask,
	// because that can only fail otherwise correct bind.
	feat := prog.MakeConstArg(typ.Fields[2], 0)
	mask := prog.MakeConstArg(typ.Fields[3], 0)
	if g.NOutOf(1, 1000) {
		feat = g.GenerateArg(typ.Fields[2], &calls).(*prog.ConstArg)
		mask = g.GenerateArg(typ.Fields[3], &calls).(*prog.ConstArg)
	}
	algType, algName := generateAlgName(g.Rand())
	// Extend/truncate type/name to their fixed sizes.
	algTypeData := fixedSizeData(algType, typ.Fields[1].Size())
	algNameData := fixedSizeData(algName, typ.Fields[4].Size())
	arg = prog.MakeGroupArg(typ, []prog.Arg{
		family,
		prog.MakeDataArg(typ.Fields[1], algTypeData),
		feat,
		mask,
		prog.MakeDataArg(typ.Fields[4], algNameData),
	})
	return
}

func (arch *arch) generateAlgName(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return generateAlgNameStruct(g, typ, allTypes[g.Rand().Intn(len(allTypes))].typ)
}

func (arch *arch) generateAlgAeadName(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return generateAlgNameStruct(g, typ, ALG_AEAD)
}

func (arch *arch) generateAlgHashName(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return generateAlgNameStruct(g, typ, ALG_HASH)
}

func (arch *arch) generateAlgBlkcipherhName(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return generateAlgNameStruct(g, typ, ALG_BLKCIPHER)
}

func generateAlgNameStruct(g *prog.Gen, typ0 prog.Type, algTyp int) (arg prog.Arg, calls []*prog.Call) {
	typ := typ0.(*prog.StructType)
	algName := generateAlg(g.Rand(), algTyp)
	algNameData := fixedSizeData(algName, typ.Fields[0].Size())
	arg = prog.MakeGroupArg(typ, []prog.Arg{
		prog.MakeDataArg(typ.Fields[0], algNameData),
	})
	return
}

func generateAlgName(rnd *rand.Rand) (string, string) {
	typ := allTypes[rnd.Intn(len(allTypes))]
	name := generateAlg(rnd, typ.typ)
	return typ.name, name
}

func generateAlg(rnd *rand.Rand, typ int) string {
	algs := allAlgs[typ]
	alg := algs[rnd.Intn(len(algs))]
	return generateAlgImpl(rnd, alg)
}

func generateAlgImpl(rnd *rand.Rand, alg algDesc) string {
	args := ""
	if len(alg.args) != 0 {
		args += "("
		for i, a := range alg.args {
			if i != 0 {
				args += ","
			}
			args += generateAlg(rnd, a)
		}
		args += ")"
	}
	return alg.name + args
}

func fixedSizeData(str string, sz uint64) []byte {
	return append([]byte(str), make([]byte, sz)...)[:sz]
}

type algType struct {
	name string
	typ  int
}

type algDesc struct {
	name string
	args []int
}

const (
	ALG_CIPHER = iota
	ALG_BLKCIPHER
	ALG_AEAD
	ALG_HASH
	ALG_RNG
)

var allTypes = []algType{
	{"aead", ALG_AEAD},
	{"skcipher", ALG_BLKCIPHER},
	{"hash", ALG_HASH},
	{"rng", ALG_RNG},
}

var allAlgs = map[int][]algDesc{
	ALG_AEAD: {
		// templates:
		{"authencesn", []int{ALG_HASH, ALG_BLKCIPHER}},
		{"authenc", []int{ALG_HASH, ALG_BLKCIPHER}},
		{"rfc7539esp", []int{ALG_BLKCIPHER, ALG_HASH}},
		{"rfc7539", []int{ALG_BLKCIPHER, ALG_HASH}},
		{"rfc4543", []int{ALG_AEAD}},
		{"rfc4106", []int{ALG_AEAD}},
		{"pcrypt", []int{ALG_AEAD}},
		{"rfc4309", []int{ALG_AEAD}},
		{"gcm", []int{ALG_CIPHER}},
		{"gcm_base", []int{ALG_BLKCIPHER, ALG_HASH}},
		{"ccm", []int{ALG_CIPHER}},
		{"ccm_base", []int{ALG_BLKCIPHER, ALG_HASH}},
		{"echainiv", []int{ALG_AEAD}},
		{"seqiv", []int{ALG_AEAD}},

		// algorithms:
		{"gcm(aes)", nil},
		{"gcm_base(ctr(aes-aesni),ghash-generic)", nil},
		{"generic-gcm-aesni", nil},
		{"rfc4106(gcm(aes))", nil},
		{"rfc4106-gcm-aesni", nil},
		{"morus640", nil},
		{"morus640-generic", nil},
		{"morus640-sse2", nil},
		{"morus1280", nil},
		{"morus1280-generic", nil},
		{"morus1280-sse2", nil},
		{"morus1280-avx2", nil},
		{"aegis128", nil},
		{"aegis128-generic", nil},
		{"aegis128-aesni", nil},
		{"aegis128l", nil},
		{"aegis128l-generic", nil},
		{"aegis128l-aesni", nil},
		{"aegis256", nil},
		{"aegis256-generic", nil},
		{"aegis256-aesni", nil},
	},
	ALG_BLKCIPHER: {
		// templates:
		{"pcbc", []int{ALG_CIPHER}},
		{"cbc", []int{ALG_CIPHER}},
		{"cfb", []int{ALG_CIPHER}},
		{"xts", []int{ALG_CIPHER}},
		{"ctr", []int{ALG_CIPHER}},
		{"lrw", []int{ALG_CIPHER}},
		{"ecb", []int{ALG_CIPHER}},
		{"kw", []int{ALG_CIPHER}},
		{"cts", []int{ALG_BLKCIPHER}},
		{"fpu", []int{ALG_BLKCIPHER}},
		{"xts", []int{ALG_BLKCIPHER}},
		{"lrw", []int{ALG_BLKCIPHER}},
		{"rfc3686", []int{ALG_BLKCIPHER}},
		{"cryptd", []int{ALG_BLKCIPHER}},

		// algorithms:
		{"cbc(aes)", nil},
		{"cbc(aes-aesni)", nil},
		{"chacha20", nil},
		{"chacha20-simd", nil},
		{"pcbc(aes)", nil},
		{"pcbc-aes-aesni", nil},
		{"fpu(pcbc(aes))", nil},
		{"fpu(pcbc(aes-aesni))", nil},
		{"pcbc(aes-aesni)", nil},
		{"xts(aes)", nil},
		{"xts-aes-aesni", nil},
		{"ctr(aes)", nil},
		{"ctr-aes-aesni", nil},
		{"cbc-aes-aesni", nil},
		{"ecb(aes)", nil},
		{"ecb-aes-aesni", nil},
		{"chacha20-generic", nil},
		{"xts(serpent)", nil},
		{"xts-serpent-avx2", nil},
		{"lrw(serpent)", nil},
		{"lrw-serpent-avx2", nil},
		{"ctr(serpent)", nil},
		{"ctr-serpent-avx2", nil},
		{"cbc(serpent)", nil},
		{"cbc-serpent-avx2", nil},
		{"ecb(serpent)", nil},
		{"ecb-serpent-avx2", nil},
		{"xts(camellia)", nil},
		{"xts-camellia-aesni-avx2", nil},
		{"lrw(camellia)", nil},
		{"lrw-camellia-aesni-avx2", nil},
		{"ctr(camellia)", nil},
		{"ctr-camellia-aesni-avx2", nil},
		{"cbc(camellia)", nil},
		{"cbc-camellia-aesni-avx2", nil},
		{"ecb(camellia)", nil},
		{"ecb-camellia-aesni-avx2", nil},
		{"xts-serpent-avx", nil},
		{"lrw-serpent-avx", nil},
		{"ctr-serpent-avx", nil},
		{"cbc-serpent-avx", nil},
		{"ecb-serpent-avx", nil},
		{"xts(twofish)", nil},
		{"xts-twofish-avx", nil},
		{"lrw(twofish)", nil},
		{"lrw-twofish-avx", nil},
		{"ctr(twofish)", nil},
		{"ctr-twofish-avx", nil},
		{"cbc(twofish)", nil},
		{"cbc-twofish-avx", nil},
		{"ecb(twofish)", nil},
		{"ecb-twofish-avx", nil},
		{"xts(cast6)", nil},
		{"xts-cast6-avx", nil},
		{"lrw(cast6)", nil},
		{"lrw-cast6-avx", nil},
		{"ctr(cast6)", nil},
		{"ctr-cast6-avx", nil},
		{"cbc(cast6)", nil},
		{"cbc-cast6-avx", nil},
		{"ecb(cast6)", nil},
		{"ecb-cast6-avx", nil},
		{"ctr(cast5)", nil},
		{"ctr-cast5-avx", nil},
		{"cbc(cast5)", nil},
		{"cbc-cast5-avx", nil},
		{"ecb(cast5)", nil},
		{"ecb-cast5-avx", nil},
		{"xts-camellia-aesni", nil},
		{"lrw-camellia-aesni", nil},
		{"ctr-camellia-aesni", nil},
		{"cbc-camellia-aesni", nil},
		{"ecb-camellia-aesni", nil},
		{"xts-serpent-sse2", nil},
		{"lrw-serpent-sse2", nil},
		{"ctr-serpent-sse2", nil},
		{"cbc-serpent-sse2", nil},
		{"ecb-serpent-sse2", nil},
		{"ctr(aes-aesni)", nil},
		{"salsa20", nil},
		{"salsa20-generic", nil},
		{"ecb(arc4)", nil},
		{"ecb(arc4)-generic", nil},
		{"ecb(cipher_null)", nil},
		{"ecb-cipher_null", nil},
		{"salsa20-asm", nil},
		{"xts-twofish-3way", nil},
		{"lrw-twofish-3way", nil},
		{"ctr-twofish-3way", nil},
		{"cbc-twofish-3way", nil},
		{"ecb-twofish-3way", nil},
		{"ctr(blowfish)", nil},
		{"ctr-blowfish-asm", nil},
		{"cbc(blowfish)", nil},
		{"cbc-blowfish-asm", nil},
		{"ecb(blowfish)", nil},
		{"ecb-blowfish-asm", nil},
		{"xts-camellia-asm", nil},
		{"lrw-camellia-asm", nil},
		{"ctr-camellia-asm", nil},
		{"cbc-camellia-asm", nil},
		{"ecb-camellia-asm", nil},
		{"ctr(des3_ede)", nil},
		{"ctr-des3_ede-asm", nil},
		{"cbc(des3_ede)", nil},
		{"cbc-des3_ede-asm", nil},
		{"ecb(des3_ede)", nil},
		{"ecb-des3_ede-asm", nil},
	},
	ALG_CIPHER: {
		{"aes", nil},
		{"aes-aesni", nil},
		{"seed", nil},
		{"seed-generic", nil},
		{"anubis", nil},
		{"anubis-generic", nil},
		{"khazad", nil},
		{"khazad-generic", nil},
		{"xeta", nil},
		{"xeta-generic", nil},
		{"xtea", nil},
		{"xtea-generic", nil},
		{"tea", nil},
		{"tea-generic", nil},
		{"arc4", nil},
		{"arc4-generic", nil},
		{"cast6", nil},
		{"cast6-generic", nil},
		{"cast5", nil},
		{"cast5-generic", nil},
		{"camellia", nil},
		{"camellia-generic", nil},
		{"camellia-asm", nil},
		{"tnepres", nil},
		{"aes-fixed-time", nil},
		{"aes-generic", nil},
		{"tnepres-generic", nil},
		{"serpent", nil},
		{"serpent-generic", nil},
		{"twofish", nil},
		{"twofish-generic", nil},
		{"twofish-asm", nil},
		{"blowfish", nil},
		{"blowfish-generic", nil},
		{"blowfish-asm", nil},
		{"fcrypt", nil},
		{"fcrypt-generic", nil},
		{"des3_ede", nil},
		{"des3_ede-generic", nil},
		{"des3_ede-asm", nil},
		{"des", nil},
		{"des-generic", nil},
		{"cipher_null", nil},
		{"cipher_null-generic", nil},
		{"aes-asm", nil},
	},
	ALG_HASH: {
		// templates:
		{"cmac", []int{ALG_CIPHER}},
		{"cbcmac", []int{ALG_CIPHER}},
		{"xcbc", []int{ALG_CIPHER}},
		{"vmac", []int{ALG_CIPHER}},
		{"hmac", []int{ALG_HASH}},
		{"mcryptd", []int{ALG_HASH}},
		{"cryptd", []int{ALG_HASH}},

		// algorithms:
		{"sha512", nil},
		{"sha512_mb", nil},
		{"sha256", nil},
		{"sha256_mb", nil},
		{"sha1", nil},
		{"sha1_mb", nil},
		{"ghash", nil},
		{"ghash-clmulni", nil},
		{"md4", nil},
		{"md4-generic", nil},
		{"md5", nil},
		{"md5-generic", nil},
		{"ghash-generic", nil},
		{"crct10dif", nil},
		{"crct10dif-generic", nil},
		{"crct10dif-pclmul", nil},
		{"crc32", nil},
		{"crc32-generic", nil},
		{"crc32c", nil},
		{"crc32c-generic", nil},
		{"michael_mic", nil},
		{"michael_mic-generic", nil},
		{"poly1305", nil},
		{"poly1305-generic", nil},
		{"tgr128", nil},
		{"tgr128-generic", nil},
		{"tgr160", nil},
		{"tgr160-generic", nil},
		{"tgr192", nil},
		{"tgr192-generic", nil},
		{"wp256", nil},
		{"wp256-generic", nil},
		{"wp384", nil},
		{"wp384-generic", nil},
		{"wp512", nil},
		{"wp512-generic", nil},
		{"sm3", nil},
		{"sm3-generic", nil},
		{"sm4", nil},
		{"sm4-generic", nil},
		{"speck128", nil},
		{"speck128-generic", nil},
		{"speck64", nil},
		{"speck64-generic", nil},
		{"sha3-512", nil},
		{"sha3-512-generic", nil},
		{"sha3-384", nil},
		{"sha3-384-generic", nil},
		{"sha3-256", nil},
		{"sha3-256-generic", nil},
		{"sha3-224", nil},
		{"sha3-224-generic", nil},
		{"sha384", nil},
		{"sha384-generic", nil},
		{"sha512-generic", nil},
		{"sha224", nil},
		{"sha224-generic", nil},
		{"sha256-generic", nil},
		{"sha1-generic", nil},
		{"rmd320", nil},
		{"rmd320-generic", nil},
		{"rmd256", nil},
		{"rmd256-generic", nil},
		{"rmd160", nil},
		{"rmd160-generic", nil},
		{"rmd128", nil},
		{"rmd128-generic", nil},
		{"digest_null", nil},
		{"digest_null-generic", nil},
		{"poly1305-simd", nil},
		{"sha384-avx2", nil},
		{"sha512-avx2", nil},
		{"sha384-avx", nil},
		{"sha512-avx", nil},
		{"sha384-ssse3", nil},
		{"sha512-ssse3", nil},
		{"sha224-avx2", nil},
		{"sha256-avx2", nil},
		{"sha224-avx", nil},
		{"sha256-avx", nil},
		{"sha224-ssse3", nil},
		{"sha256-ssse3", nil},
		{"crc32-pclmul", nil},
		{"sha1-avx2", nil},
		{"sha1-avx", nil},
		{"sha1-ssse3", nil},
		{"crc32c-intel", nil},
	},
	ALG_RNG: {
		{"stdrng", nil},
		{"ansi_cprng", nil},
		{"jitterentropy_rng", nil},
		{"drbg_nopr_hmac_sha256", nil},
		{"drbg_nopr_hmac_sha512", nil},
		{"drbg_nopr_hmac_sha384", nil},
		{"drbg_nopr_hmac_sha1", nil},
		{"drbg_nopr_sha256", nil},
		{"drbg_nopr_sha512", nil},
		{"drbg_nopr_sha384", nil},
		{"drbg_nopr_sha1", nil},
		{"drbg_nopr_ctr_aes256", nil},
		{"drbg_nopr_ctr_aes192", nil},
		{"drbg_nopr_ctr_aes128", nil},
		{"drbg_pr_hmac_sha256", nil},
		{"drbg_pr_hmac_sha512", nil},
		{"drbg_pr_hmac_sha384", nil},
		{"drbg_pr_hmac_sha1", nil},
		{"drbg_pr_sha256", nil},
		{"drbg_pr_sha512", nil},
		{"drbg_pr_sha384", nil},
		{"drbg_pr_sha1", nil},
		{"drbg_pr_ctr_aes256", nil},
		{"drbg_pr_ctr_aes192", nil},
		{"drbg_pr_ctr_aes128", nil},
	},
}
