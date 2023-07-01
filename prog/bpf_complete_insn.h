#include "bpf_insn.h"

/**************************** ALU ***************************/

#define BPF_NEG64_REG(DST)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU64 | BPF_OP(BPF_NEG),    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_NEG32_REG(DST)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_OP(BPF_NEG),    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_ENDBE_REG(DST, IMM)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_TO_BE | BPF_END,    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = IMM })

#define BPF_ENDLE_REG(DST, IMM)             \
    ((struct bpf_insn) {                    \
        .code  = BPF_ALU | BPF_TO_LE | BPF_END,    \
        .dst_reg = DST,                 \
        .src_reg = 0,                 \
        .off   = 0,                 \
        .imm   = IMM }) // imm = 16, 32, 64

/**************************** Load/Store ***************************/

/*
 * insn[0].src_reg:  BPF_PSEUDO_MAP_[FD|IDX]
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map
 * verifier type:    CONST_PTR_TO_MAP
*/
#define BPF_PSEUDO_MAP_IDX  5
#define BPF_LD_FDIDX(DST, MAP_FDIDX)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_IDX, MAP_FDIDX)


/* insn[0].src_reg:  BPF_PSEUDO_MAP_[IDX_]VALUE
 * insn[0].imm:      map fd or fd_idx
 * insn[1].imm:      offset into value
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of map[0]+offset
 * verifier type:    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_VALUE        2
#define BPF_PSEUDO_MAP_IDX_VALUE    6
#define BPF_LD_FD_MAPVALUE(DST, FD, OFF)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_VALUE, (((__u64)OFF<<32 | FD)))
#define BPF_LD_FDIDX_MAPVALUE(DST, FDIDX, OFF)             \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_IDX_VALUE, (OFF<<32 | FDIDX))


/* insn[0].src_reg:  BPF_PSEUDO_BTF_ID
 * insn[0].imm:      kernel btd id of VAR
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the kernel variable
 * verifier type:    PTR_TO_BTF_ID or PTR_TO_MEM, depending on whether the var
 *                   is struct/union.
 */
#define BPF_PSEUDO_BTF_ID   3
// TAO TODO

/* insn[0].src_reg:  BPF_PSEUDO_FUNC
 * insn[0].imm:      insn offset to the func
 * insn[1].imm:      0
 * insn[0].off:      0
 * insn[1].off:      0
 * ldimm64 rewrite:  address of the function
 * verifier type:    PTR_TO_FUNC.
 since the second instruction is not used at all. Define it with one instruction.
 */
#define BPF_PSEUDO_FUNC     4
#define BPF_LD_PSEUDO_FUNC(DST, OFF) \
        BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, DST, BPF_PSEUDO_FUNC, 0, OFF)

// Packet data at a variable offset (BPF_IND)
#define BPF_LD_IND(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })

/*
// The packet length (BPF_LEN)
#define BPF_LD_LEN(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_LEN, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })
// Loading the IP header length
#define BPF_LD_MSH(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_MSH, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })
*/


/**************************** JMP ***************************/

#define BPF_JA_INSN(OFF) BPF_RAW_INSN(BPF_JMP | BPF_JA, 0, 0, OFF, 0)


/**************************** Call ***************************/

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL     1
#define BPF_CALL_PSEUDO_FUNC(PCOFF)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_JMP | BPF_CALL,            \
        .dst_reg = 0,                   \
        .src_reg = BPF_PSEUDO_CALL,         \
        .off   = 0,                 \
        .imm   = PCOFF })


/* when bpf_call->src_reg == BPF_PSEUDO_KFUNC_CALL,
 * bpf_call->imm == btf_id of a BTF_KIND_FUNC in the running kernel
 */
#define BPF_PSEUDO_KFUNC_CALL   2
// TAO TODO

#define BPF_HELPER_CALL(HELPER) BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, HELPER)