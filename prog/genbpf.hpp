#include <stdio.h>
#include <stdlib.h>
#include <time.h>
//#include <bpf/bpf.h>
//#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>

#include "bpf_insn.h"

#define NINSNS 10
#define NINSNSALL (NINSNS+3)
#define SMAX 

#define Bit64 0b01
#define Bit32 0b10

#define    ALU64_REG 0b111
#define    ALU32_REG 0b101
#define    ALU64_IMM 0b110
#define    ALU32_IMM 0b100
#define    MOV64_REG 0b011
#define    MOV32_REG 0b001
#define    MOV64_IMM 0b010
#define    MOV32_IMM 0b000

enum operations{
    ALUOP,
    LSOP,
    JMPOP,
    HELPER,
    SUBFUNC,
};

enum bpf_reg_type {
    NOT_INIT = 0,        /* nothing was written into register */
    SCALAR_VALUE,        /* reg doesn't contain a valid pointer */
    PTR_TO_CTX,      /* reg points to bpf_context */
    CONST_PTR_TO_MAP,    /* reg points to struct bpf_map */
    PTR_TO_MAP_VALUE,    /* reg points to map element value */
    PTR_TO_MAP_KEY,      /* reg points to a map element key */
    PTR_TO_STACK,        /* reg == frame_pointer + offset */
    PTR_TO_PACKET_META,  /* skb->data - meta_len */
    PTR_TO_PACKET,       /* reg points to skb->data */
    PTR_TO_PACKET_END,   /* skb->data + headlen */
    PTR_TO_FLOW_KEYS,    /* reg points to bpf_flow_keys */
    PTR_TO_SOCKET,       /* reg points to struct bpf_sock */
    PTR_TO_SOCK_COMMON,  /* reg points to sock_common */
    PTR_TO_TCP_SOCK,     /* reg points to struct tcp_sock */
    PTR_TO_TP_BUFFER,    /* reg points to a writable raw tp's buffer */
    PTR_TO_XDP_SOCK,
    PTR_TO_BTF_ID,
    /* PTR_TO_BTF_ID_OR_NULL points to a kernel struct that has not
     * been checked for null. Used primarily to inform the verifier
     * an explicit null check is required for this struct.
     */
    PTR_TO_MEM,      /* reg points to valid memory region */
    PTR_TO_BUF,      /* reg points to a read/write buffer */
    PTR_TO_FUNC,         /* reg points to a bpf program function */
    CONST_PTR_TO_DYNPTR,     /* reg points to a const struct bpf_dynptr */
    __BPF_REG_TYPE_MAX,
};

struct regState {
	int type;
};

char logbuf[1024 * 1024];
char licenseString[] = "Dual BSD/GPL";

void genALUOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt);
void genLSOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int maxMaps);
void genJMPOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt);
void printInsn(const char *insn, u_int8_t op, u_int8_t dst, u_int8_t src, int32_t imm, short int off) {
    fprintf(stderr, "%s_%d(dst %d, src %d, imm %d, off %d)\n", insn, op, dst, src, imm, off);
}

/*
    #define     BPF_ADD     0x00
    #define     BPF_SUB     0x10
    #define     BPF_MUL     0x20
    #define     BPF_DIV     0x30
    #define     BPF_OR      0x40
    #define     BPF_AND     0x50
    #define     BPF_LSH     0x60
    #define     BPF_RSH     0x70
    #define     BPF_NEG     0x80
    #define     BPF_MOD     0x90
    #define     BPF_XOR     0xa0
*/

__u8 aluops[] = {
    BPF_ADD,
    BPF_SUB,
    BPF_MUL,
    BPF_DIV,
    BPF_OR,
    BPF_AND,
    BPF_LSH,
    BPF_RSH,
    BPF_NEG,
    BPF_MOD,
    BPF_XOR,
};

__u8 jmpops[] = {
    // BPF_JA,
    BPF_JEQ,
    BPF_JGT,
    BPF_JGE,
    BPF_JSET,
    BPF_JNE,
    BPF_JLT,
    BPF_JLE,
    BPF_JSGT,
    BPF_JSGE,
    BPF_JSLT,
    BPF_JSLE,
};

#define BPF_JA_INSN(OFF) BPF_RAW_INSN(BPF_JA, 0, 0, OFF, 0)

__u8 regs[] = {
    BPF_REG_0,
    BPF_REG_1,
    BPF_REG_2,
    BPF_REG_3,
    BPF_REG_4,
    BPF_REG_5,
    BPF_REG_6,
    BPF_REG_7,
    BPF_REG_8,
    BPF_REG_9,
    BPF_REG_10,
};

__u8 SIZE[] = {
    BPF_W,
    BPF_H,
    BPF_B,
    BPF_DW,
};

#define BPF_FETCH	0x01
#define BPF_XCHG	(0xe0 | BPF_FETCH)
#define BPF_CMPXCHG	(0xf0 | BPF_FETCH)
#define BPF_ATOMIC	0xc0

__u8 atomicOps[] = {
    BPF_ADD,
    BPF_AND,
    BPF_OR,
    BPF_XOR,
    BPF_ADD | BPF_FETCH,
    BPF_AND | BPF_FETCH,
    BPF_OR | BPF_FETCH,
    BPF_XOR | BPF_FETCH,
    BPF_XCHG,
    BPF_CMPXCHG,
};

struct regState regStates[sizeof(regs)];

#define stateTransit(dst, src) (dst.type = src.type)

// BPF_PSEUDO_MAP_[IDX_]VALUE
// BPF_PSEUDO_BTF_ID
// BPF_PSEUDO_MAP_[FD|IDX]
/*
184:#define BPF_PSEUDO_MAP_IDX	5
1195:#define BPF_PSEUDO_MAP_IDX_VALUE	6
302:#define BPF_PSEUDO_MAP_FD	1
#define BPF_PSEUDO_MAP_IDX_VALUE	6
*/

// the packet length (BPF_LEN)
#define BPF_LD_LEN(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_LEN, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })

// packet data at a variable offset (BPF_IND)
#define BPF_LD_IND(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })

// loading the IP header length
#define BPF_LD_MSH(SIZE, IMM)                   \
    ((struct bpf_insn) {                    \
        .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_MSH, \
        .dst_reg = 0,                   \
        .src_reg = 0,                   \
        .off   = 0,                 \
        .imm   = IMM })

inline int32_t randNum32() {
    int32_t num = rand();
    return num % 2 == 1 ? num : num - RAND_MAX;
}

inline int64_t randNum64() {
    int64_t num = rand();
    return num % 2 == 1 ? num : num - RAND_MAX;
}

inline Json::Value readJsonFile(char *fname) {
    Json::Value jsonData;
    std::ifstream jsonFile(fname, std::ifstream::binary);
    jsonFile >> jsonData;
    return jsonData;
}

Json::Value progTypes;
Json::Value progType2Helpers;
Json::Value dataflowGraph;
int ptCnt;
//
int nAllowedHelpers = 0;
Json::Value allowedHelpers;

void genInit() {

    // progType
    progTypes = readJsonFile((char *)"./bpf-info/progtypes");
    ptCnt = progTypes.size();
    
    // Corresponding helpers
    progType2Helpers = readJsonFile((char *)"./bpf-info/progtype_helpers");

    // dataflowGraph
    dataflowGraph = readJsonFile((char *)"./bpf-info/helper_dataflow");
}

struct bpf_insn bpfBytecode[NINSNSALL];

void PrintLogbuf(char *bpfAttrArg){
	union bpf_attr *bpfAttr = (union bpf_attr *)bpfAttrArg;
	fprintf(stderr, "log_buf:%s\n", (char *)bpfAttr->log_buf);
}

bool updateByteCode(bool genNewInsn, struct bpf_insn *bpfBytecode, int *cnt, struct bpf_insn insn) {
    if (genNewInsn && *cnt < NINSNS) {
        bpfBytecode[*cnt] = insn;
        *cnt += 1;
        return true;
    }
    return false;
}

bool initRegScalar(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {
    
    // The reg has already been initilized
    if (regStates[reg].type != NOT_INIT) return true;

    struct bpf_insn insn;
    int32_t imm32, imm64;
    switch (regBit) {
        case Bit32:
            imm32 = randNum32();
            insn = BPF_MOV32_IMM(reg, imm32);
            printInsn("BPF_MOV32_IMM", 0, reg, 0, imm32, 0);
            break;
        case Bit64:
            imm64 = randNum64();
            insn = BPF_MOV64_IMM(reg, imm64);
            printInsn("BPF_MOV64_IMM", 0, reg, 0, imm64, 0);
            break;
    }

    bool ret = updateByteCode(true, bpfBytecode, cnt, insn);
    if (ret) regStates[reg].type = SCALAR_VALUE;

    return true;
}

bool initRegPtr(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {
    
    if (regStates[reg].type == PTR_TO_CTX && regStates[reg].type == PTR_TO_STACK) return true;

    struct bpf_insn insn;
    for (int i = 0; i < sizeof(regs); i++) {
        switch(regStates[i].type) {
            case PTR_TO_CTX:
            case PTR_TO_STACK:
                insn = BPF_MOV64_REG(reg, i);
                updateByteCode(true, bpfBytecode, cnt, insn);
                return true;
        }
    }

    // TODO

    return false;
}

bool BPF_ALU64_REG_Constraint(u_int8_t op, u_int8_t dst, u_int8_t src, int32_t imm, short int off) {
    
    if (op == BPF_NEG && src != 0) return false;
    return true;
}

bool BPF_ALU32_REG_Constraint(u_int8_t op, u_int8_t dst, u_int8_t src, int32_t imm, short int off) {
    
    if (op == BPF_NEG && src != 0) return false;
    return true;
}

bool BPF_ATOMIC_OP_Constrait(int size, u_int8_t op, u_int8_t dst, u_int8_t src, short int off) {
    
    if (size != BPF_DW && size != BPF_W) return false;
    return true;
}