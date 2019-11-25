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

func (arch *arch) generateAlgSkcipherhName(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return generateAlgNameStruct(g, typ, ALG_SKCIPHER)
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
	ALG_SKCIPHER
	ALG_AEAD
	ALG_HASH
	ALG_RNG
)

var allTypes = []algType{
	{"aead", ALG_AEAD},
	{"skcipher", ALG_SKCIPHER},
	{"hash", ALG_HASH},
	{"rng", ALG_RNG},
}

var allAlgs = map[int][]algDesc{
	ALG_AEAD: {
		// templates:
		{"authenc", []int{ALG_HASH, ALG_SKCIPHER}},
		{"authencesn", []int{ALG_HASH, ALG_SKCIPHER}},
		{"ccm", []int{ALG_CIPHER}},
		{"ccm_base", []int{ALG_SKCIPHER, ALG_HASH}},
		{"echainiv", []int{ALG_AEAD}},
		{"essiv", []int{ALG_AEAD, ALG_HASH}},
		{"gcm", []int{ALG_CIPHER}},
		{"gcm_base", []int{ALG_SKCIPHER, ALG_HASH}},
		{"pcrypt", []int{ALG_AEAD}},
		{"rfc4106", []int{ALG_AEAD}},
		{"rfc4309", []int{ALG_AEAD}},
		{"rfc4543", []int{ALG_AEAD}},
		{"rfc7539", []int{ALG_SKCIPHER, ALG_HASH}},
		{"rfc7539esp", []int{ALG_SKCIPHER, ALG_HASH}},
		{"seqiv", []int{ALG_AEAD}},

		// algorithms:
		{"aegis128", nil},
		{"aegis128-aesni", nil},
		{"aegis128-generic", nil},
		{"aegis128l", nil},
		{"aegis128l-aesni", nil},
		{"aegis128l-generic", nil},
		{"aegis256", nil},
		{"aegis256-aesni", nil},
		{"aegis256-generic", nil},
		{"ccm-aes-ce", nil},
		{"gcm(aes)", nil},
		{"gcm-aes-ce", nil},
		{"gcm_base(ctr(aes-aesni),ghash-generic)", nil},
		{"generic-gcm-aesni", nil},
		{"morus1280", nil},
		{"morus1280-avx2", nil},
		{"morus1280-generic", nil},
		{"morus1280-sse2", nil},
		{"morus640", nil},
		{"morus640-generic", nil},
		{"morus640-sse2", nil},
		{"rfc4106(gcm(aes))", nil},
		{"rfc4106-gcm-aesni", nil},
	},
	ALG_SKCIPHER: {
		// templates:
		{"adiantum", []int{ALG_SKCIPHER, ALG_CIPHER, ALG_HASH}},
		{"adiantum", []int{ALG_SKCIPHER, ALG_CIPHER}},
		{"cbc", []int{ALG_CIPHER}},
		{"cfb", []int{ALG_CIPHER}},
		{"cryptd", []int{ALG_SKCIPHER}},
		{"ctr", []int{ALG_CIPHER}},
		{"cts", []int{ALG_SKCIPHER}},
		{"ecb", []int{ALG_CIPHER}},
		{"essiv", []int{ALG_SKCIPHER, ALG_HASH}},
		{"fpu", []int{ALG_SKCIPHER}},
		{"kw", []int{ALG_CIPHER}},
		{"lrw", []int{ALG_SKCIPHER}},
		{"lrw", []int{ALG_CIPHER}},
		{"ofb", []int{ALG_CIPHER}},
		{"pcbc", []int{ALG_CIPHER}},
		{"rfc3686", []int{ALG_SKCIPHER}},
		{"xts", []int{ALG_SKCIPHER}},
		{"xts", []int{ALG_CIPHER}},

		// algorithms:
		{"cbc(aes)", nil},
		{"cbc(aes-aesni)", nil},
		{"cbc(blowfish)", nil},
		{"cbc(camellia)", nil},
		{"cbc(cast5)", nil},
		{"cbc(cast6)", nil},
		{"cbc(des3_ede)", nil},
		{"cbc(serpent)", nil},
		{"cbc(twofish)", nil},
		{"cbc-aes-aesni", nil},
		{"cbc-aes-ce", nil},
		{"cbc-aes-neon", nil},
		{"cbc-blowfish-asm", nil},
		{"cbc-camellia-aesni", nil},
		{"cbc-camellia-aesni-avx2", nil},
		{"cbc-camellia-asm", nil},
		{"cbc-cast5-avx", nil},
		{"cbc-cast6-avx", nil},
		{"cbc-des3_ede-asm", nil},
		{"cbc-serpent-avx", nil},
		{"cbc-serpent-avx2", nil},
		{"cbc-serpent-sse2", nil},
		{"cbc-twofish-3way", nil},
		{"cbc-twofish-avx", nil},
		{"chacha20", nil},
		{"chacha20-arm", nil},
		{"chacha20-generic", nil},
		{"chacha20-neon", nil},
		{"chacha20-simd", nil},
		{"ctr(aes)", nil},
		{"ctr(aes-aesni)", nil},
		{"ctr(blowfish)", nil},
		{"ctr(camellia)", nil},
		{"ctr(cast5)", nil},
		{"ctr(cast6)", nil},
		{"ctr(des3_ede)", nil},
		{"ctr(serpent)", nil},
		{"ctr(twofish)", nil},
		{"ctr-aes-aesni", nil},
		{"ctr-aes-ce", nil},
		{"ctr-aes-neon", nil},
		{"ctr-aes-neonbs", nil},
		{"ctr-blowfish-asm", nil},
		{"ctr-camellia-aesni", nil},
		{"ctr-camellia-aesni-avx2", nil},
		{"ctr-camellia-asm", nil},
		{"ctr-cast5-avx", nil},
		{"ctr-cast6-avx", nil},
		{"ctr-des3_ede-asm", nil},
		{"ctr-serpent-avx", nil},
		{"ctr-serpent-avx2", nil},
		{"ctr-serpent-sse2", nil},
		{"ctr-twofish-3way", nil},
		{"ctr-twofish-avx", nil},
		{"ecb(aes)", nil},
		{"ecb(arc4)", nil},
		{"ecb(arc4)-generic", nil},
		{"ecb(blowfish)", nil},
		{"ecb(camellia)", nil},
		{"ecb(cast5)", nil},
		{"ecb(cast6)", nil},
		{"ecb(cipher_null)", nil},
		{"ecb(des3_ede)", nil},
		{"ecb(serpent)", nil},
		{"ecb(twofish)", nil},
		{"ecb-aes-aesni", nil},
		{"ecb-aes-ce", nil},
		{"ecb-aes-neon", nil},
		{"ecb-blowfish-asm", nil},
		{"ecb-camellia-aesni", nil},
		{"ecb-camellia-aesni-avx2", nil},
		{"ecb-camellia-asm", nil},
		{"ecb-cast5-avx", nil},
		{"ecb-cast6-avx", nil},
		{"ecb-cipher_null", nil},
		{"ecb-des3_ede-asm", nil},
		{"ecb-serpent-avx", nil},
		{"ecb-serpent-avx2", nil},
		{"ecb-serpent-sse2", nil},
		{"ecb-twofish-3way", nil},
		{"ecb-twofish-avx", nil},
		{"fpu(pcbc(aes))", nil},
		{"fpu(pcbc(aes-aesni))", nil},
		{"lrw(camellia)", nil},
		{"lrw(cast6)", nil},
		{"lrw(serpent)", nil},
		{"lrw(twofish)", nil},
		{"lrw-camellia-aesni", nil},
		{"lrw-camellia-aesni-avx2", nil},
		{"lrw-camellia-asm", nil},
		{"lrw-cast6-avx", nil},
		{"lrw-serpent-avx", nil},
		{"lrw-serpent-avx2", nil},
		{"lrw-serpent-sse2", nil},
		{"lrw-twofish-3way", nil},
		{"lrw-twofish-avx", nil},
		{"pcbc(aes)", nil},
		{"pcbc(aes-aesni)", nil},
		{"pcbc-aes-aesni", nil},
		{"salsa20", nil},
		{"salsa20-asm", nil},
		{"salsa20-generic", nil},
		{"xchacha12", nil},
		{"xchacha12-arm", nil},
		{"xchacha12-generic", nil},
		{"xchacha12-neon", nil},
		{"xchacha12-simd", nil},
		{"xchacha20", nil},
		{"xchacha20-arm", nil},
		{"xchacha20-generic", nil},
		{"xchacha20-neon", nil},
		{"xchacha20-simd", nil},
		{"xts(aes)", nil},
		{"xts(camellia)", nil},
		{"xts(cast6)", nil},
		{"xts(serpent)", nil},
		{"xts(twofish)", nil},
		{"xts-aes-aesni", nil},
		{"xts-aes-ce", nil},
		{"xts-aes-neon", nil},
		{"xts-camellia-aesni", nil},
		{"xts-camellia-aesni-avx2", nil},
		{"xts-camellia-asm", nil},
		{"xts-cast6-avx", nil},
		{"xts-serpent-avx", nil},
		{"xts-serpent-avx2", nil},
		{"xts-serpent-sse2", nil},
		{"xts-twofish-3way", nil},
		{"xts-twofish-avx", nil},
	},
	ALG_CIPHER: {
		{"aes", nil},
		{"aes-aesni", nil},
		{"aes-arm64", nil},
		{"aes-asm", nil},
		{"aes-ce", nil},
		{"aes-fixed-time", nil},
		{"aes-generic", nil},
		{"anubis", nil},
		{"anubis-generic", nil},
		{"arc4", nil},
		{"arc4-generic", nil},
		{"blowfish", nil},
		{"blowfish-asm", nil},
		{"blowfish-generic", nil},
		{"camellia", nil},
		{"camellia-asm", nil},
		{"camellia-generic", nil},
		{"cast5", nil},
		{"cast5-generic", nil},
		{"cast6", nil},
		{"cast6-generic", nil},
		{"cipher_null", nil},
		{"cipher_null-generic", nil},
		{"des", nil},
		{"des-generic", nil},
		{"des3_ede", nil},
		{"des3_ede-asm", nil},
		{"des3_ede-generic", nil},
		{"fcrypt", nil},
		{"fcrypt-generic", nil},
		{"khazad", nil},
		{"khazad-generic", nil},
		{"seed", nil},
		{"seed-generic", nil},
		{"serpent", nil},
		{"serpent-generic", nil},
		{"sm4", nil},
		{"sm4-ce", nil},
		{"sm4-generic", nil},
		{"tea", nil},
		{"tea-generic", nil},
		{"tnepres", nil},
		{"tnepres-generic", nil},
		{"twofish", nil},
		{"twofish-asm", nil},
		{"twofish-generic", nil},
		{"xeta", nil},
		{"xeta-generic", nil},
		{"xtea", nil},
		{"xtea-generic", nil},
	},
	ALG_HASH: {
		// templates:
		{"cbcmac", []int{ALG_CIPHER}},
		{"cmac", []int{ALG_CIPHER}},
		{"cryptd", []int{ALG_HASH}},
		{"hmac", []int{ALG_HASH}},
		{"mcryptd", []int{ALG_HASH}},
		{"vmac", []int{ALG_CIPHER}},
		{"vmac64", []int{ALG_CIPHER}},
		{"xcbc", []int{ALG_CIPHER}},

		// algorithms:
		{"blake2b-160", nil},
		{"blake2b-160-generic", nil},
		{"blake2b-256", nil},
		{"blake2b-256-generic", nil},
		{"blake2b-384", nil},
		{"blake2b-384-generic", nil},
		{"blake2b-512", nil},
		{"blake2b-512-generic", nil},
		{"blake2s-128", nil},
		{"blake2s-128-generic", nil},
		{"blake2s-128-x86", nil},
		{"blake2s-160", nil},
		{"blake2s-160-generic", nil},
		{"blake2s-160-x86", nil},
		{"blake2s-224", nil},
		{"blake2s-224-generic", nil},
		{"blake2s-224-x86", nil},
		{"blake2s-256", nil},
		{"blake2s-256-generic", nil},
		{"blake2s-256-x86", nil},
		{"cbcmac-aes-ce", nil},
		{"cbcmac-aes-neon", nil},
		{"cmac-aes-ce", nil},
		{"cmac-aes-neon", nil},
		{"crc32", nil},
		{"crc32-generic", nil},
		{"crc32-pclmul", nil},
		{"crc32c", nil},
		{"crc32c-generic", nil},
		{"crc32c-intel", nil},
		{"crct10dif", nil},
		{"crct10dif-arm64-ce", nil},
		{"crct10dif-generic", nil},
		{"crct10dif-pclmul", nil},
		{"digest_null", nil},
		{"digest_null-generic", nil},
		{"ghash", nil},
		{"ghash-ce", nil},
		{"ghash-clmulni", nil},
		{"ghash-generic", nil},
		{"md4", nil},
		{"md4-generic", nil},
		{"md5", nil},
		{"md5-generic", nil},
		{"michael_mic", nil},
		{"michael_mic-generic", nil},
		{"nhpoly1305", nil},
		{"nhpoly1305-avx2", nil},
		{"nhpoly1305-generic", nil},
		{"nhpoly1305-neon", nil},
		{"nhpoly1305-sse2", nil},
		{"poly1305", nil},
		{"poly1305-arm", nil},
		{"poly1305-generic", nil},
		{"poly1305-neon", nil},
		{"poly1305-simd", nil},
		{"rmd128", nil},
		{"rmd128-generic", nil},
		{"rmd160", nil},
		{"rmd160-generic", nil},
		{"rmd256", nil},
		{"rmd256-generic", nil},
		{"rmd320", nil},
		{"rmd320-generic", nil},
		{"sha1", nil},
		{"sha1-avx", nil},
		{"sha1-avx2", nil},
		{"sha1-ce", nil},
		{"sha1-generic", nil},
		{"sha1-ni", nil},
		{"sha1-ssse3", nil},
		{"sha1_mb", nil},
		{"sha224", nil},
		{"sha224-arm64", nil},
		{"sha224-arm64-neon", nil},
		{"sha224-avx", nil},
		{"sha224-avx2", nil},
		{"sha224-ce", nil},
		{"sha224-generic", nil},
		{"sha224-ni", nil},
		{"sha224-ssse3", nil},
		{"sha256", nil},
		{"sha256-arm64", nil},
		{"sha256-arm64-neon", nil},
		{"sha256-avx", nil},
		{"sha256-avx2", nil},
		{"sha256-ce", nil},
		{"sha256-generic", nil},
		{"sha256-ni", nil},
		{"sha256-ssse3", nil},
		{"sha256_mb", nil},
		{"sha3-224", nil},
		{"sha3-224-ce", nil},
		{"sha3-224-generic", nil},
		{"sha3-256", nil},
		{"sha3-256-ce", nil},
		{"sha3-256-generic", nil},
		{"sha3-384", nil},
		{"sha3-384-ce", nil},
		{"sha3-384-generic", nil},
		{"sha3-512", nil},
		{"sha3-512-ce", nil},
		{"sha3-512-generic", nil},
		{"sha384", nil},
		{"sha384-arm64", nil},
		{"sha384-avx", nil},
		{"sha384-avx2", nil},
		{"sha384-ce", nil},
		{"sha384-generic", nil},
		{"sha384-ssse3", nil},
		{"sha512", nil},
		{"sha512-arm64", nil},
		{"sha512-avx", nil},
		{"sha512-avx2", nil},
		{"sha512-ce", nil},
		{"sha512-generic", nil},
		{"sha512-ssse3", nil},
		{"sha512_mb", nil},
		{"sm3", nil},
		{"sm3-ce", nil},
		{"sm3-generic", nil},
		{"streebog256", nil},
		{"streebog256-generic", nil},
		{"streebog512", nil},
		{"streebog512-generic", nil},
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
		{"xcbc-aes-ce", nil},
		{"xcbc-aes-neon", nil},
		{"xxhash64", nil},
		{"xxhash64-generic", nil},
	},
	ALG_RNG: {
		{"ansi_cprng", nil},
		{"drbg_nopr_ctr_aes128", nil},
		{"drbg_nopr_ctr_aes192", nil},
		{"drbg_nopr_ctr_aes256", nil},
		{"drbg_nopr_hmac_sha1", nil},
		{"drbg_nopr_hmac_sha256", nil},
		{"drbg_nopr_hmac_sha384", nil},
		{"drbg_nopr_hmac_sha512", nil},
		{"drbg_nopr_sha1", nil},
		{"drbg_nopr_sha256", nil},
		{"drbg_nopr_sha384", nil},
		{"drbg_nopr_sha512", nil},
		{"drbg_pr_ctr_aes128", nil},
		{"drbg_pr_ctr_aes192", nil},
		{"drbg_pr_ctr_aes256", nil},
		{"drbg_pr_hmac_sha1", nil},
		{"drbg_pr_hmac_sha256", nil},
		{"drbg_pr_hmac_sha384", nil},
		{"drbg_pr_hmac_sha512", nil},
		{"drbg_pr_sha1", nil},
		{"drbg_pr_sha256", nil},
		{"drbg_pr_sha384", nil},
		{"drbg_pr_sha512", nil},
		{"jitterentropy_rng", nil},
		{"stdrng", nil},
	},
}
