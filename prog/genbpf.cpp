#include "genbpf.hpp"
#include "genmap.hpp"
#include "genbpfimport.hpp"

/* TODO:
    1. state transition in each instruction
        x ALU
        LOAD/STORE
        CALL
    2. proceding instructions
    3. memory access offset generation according to ptr states
    4. JMP location
*/

int GenBPFProg(char *bpfProgAttr, char *bpfMapAttr, int MaxMapAttrSize) {

	insnSize = NINSNSALL * sizeof(struct bpf_insn);
	licenseSize = sizeof(licenseString);
	funcInfoSize = 0;
	lineInfoSize = 0;
    
    memset(bpfProgAttr, 0, MaxMapAttrSize);
    memset(bpfProgAttr, 0, MaxMapAttrSize);

	union bpf_attr *progAttr = (union bpf_attr *)bpfProgAttr;
    union bpf_attr *mapAttrs = (union bpf_attr *)bpfMapAttr;
	
	// Initialize some global variables
	// genInit();

    // progType
    progAttr->prog_type = 1; // progTypes[rand() % ptCnt].asCString();
	progAttr->license = (__u64)licenseString;
	progAttr->log_level = 2;
	progAttr->log_size = 1024*1024;
	progAttr->log_buf = (__u64)logbuf;
    // Corresponding helpers
    // allowedHelpers = progType2Helpers[progType];
    // nAllowedHelpers = allowedHelpers.size();

    // Initialize bpf map attributes
    int maxMaps = rand() % (MaxMapAttrSize / sizeof(union bpf_attr));
    for (int i = 0; i < maxMaps; i++) {
        union bpf_attr *mapAttr = mapAttrs + i;
        createOneMap(mapAttr);
    }

    // TODO: regStates
    struct regState regStates[11] = {NOT_INIT};
    regStates[1].type = PTR_TO_CTX;
    regStates[10].type = PTR_TO_STACK;

    int cnt;
    for(cnt = 0; cnt < NINSNS; ){
        switch(rand() % 4){
            case ALUOP:
                genALUOP(regStates, bpfBytecode, &cnt);                
                break;
            case LSOP:
                genLSOP(regStates, bpfBytecode, &cnt, maxMaps);
                break;
            case JMPOP:
                genJMPOP(regStates, bpfBytecode, &cnt);
                break;            
            case CALLOP:
                genCallOP(regStates, bpfBytecode, &cnt);
                break;
        }
    }

    if (regStates[0].type == NOT_INIT) {
        bpfBytecode[cnt] = BPF_MOV64_IMM(0, 0);
        printInsn("BPF_MOV64_IMM", 0, 0, 0, 0, 0);
        cnt += 1;
    }
    bpfBytecode[cnt] = BPF_EXIT_INSN();
    printInsn("BPF_EXIT_INSN", 0, 0, 0, 0, 0);
    cnt += 1;
    
	progAttr->insns = (__u64)bpfBytecode;
	progAttr->insn_cnt = cnt;

    // return sizeof(union bpf_attr);
    return maxMaps;
}

void genALUOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {
    
    /*
        BPF_ALU64_REG(OP, DST, SRC);
        BPF_ALU32_REG(OP, DST, SRC);
        BPF_ALU64_IMM(OP, DST, IMM)
        BPF_ALU32_IMM(OP, DST, IMM)

        BPF_MOV64_REG(DST, SRC)
        BPF_MOV32_REG(DST, SRC)
        BPF_MOV64_IMM(DST, IMM)
        BPF_MOV32_IMM(DST, IMM)
    */

    // __u8 AluMov = (rand() % 2) << 2;
    // __u8 Bit6432 = (rand() % 2) << 1;
    // __u8 RegImm = (rand() % 2);

    __u8 op = aluops[rand() % sizeof(aluops)];
    u_int8_t dst = regs[rand() % (sizeof(regs)-1)], src = regs[rand() % sizeof(regs)];
    int32_t imm32 = randNum32(), imm64 = randNum32();
    struct bpf_insn insn;

    // switch(AluMov | Bit6432 | RegImm) {
    switch (rand() % 10) {
        case 0:
            if (BPF_ALU64_REG_Constraint(op, dst, src, 0, 0)) {
                initRegScalar(src, Bit64, regStates, bpfBytecode, cnt);
                initRegScalar(dst, Bit64, regStates, bpfBytecode, cnt);
                insn = BPF_ALU64_REG(op, dst, src);
                regStates[dst].type = regStates[src].type;
                printInsn("BPF_ALU64_REG", op, dst, src, 0, 0);
            }
            break;
        case 1:
            if (BPF_ALU32_REG_Constraint(op, dst, src, 0, 0)) {
                initRegScalar(src, Bit32, regStates, bpfBytecode, cnt);
                initRegScalar(dst, Bit32, regStates, bpfBytecode, cnt);
                insn = BPF_ALU32_REG(op, dst, src);
                regStates[dst].type = regStates[src].type;
                printInsn("BPF_ALU32_REG", op, dst, src, 0, 0);
            }
            break;
        case 2:
            initRegScalar(dst, Bit64, regStates, bpfBytecode, cnt);
            insn = BPF_ALU64_IMM(op, dst, imm64);
            regStates[dst].type = SCALAR_VALUE;
            printInsn("BPF_ALU64_IMM", op, dst, 0, imm64, 0);
            break;
        case 3:
            initRegScalar(dst, Bit32, regStates, bpfBytecode, cnt);
            insn = BPF_ALU32_IMM(op, dst, imm32);
            regStates[dst].type = SCALAR_VALUE;
            printInsn("BPF_ALU32_IMM", op, dst, 0, imm32, 0);
            break;
        case 4:
            initRegScalar(src, Bit64, regStates, bpfBytecode, cnt);
            insn = BPF_MOV64_REG(dst, src);
            regStates[dst].type = regStates[src].type;
            printInsn("BPF_MOV64_REG", 0, dst, src, 0, 0);
            break;
        case 5:
            initRegScalar(src, Bit32, regStates, bpfBytecode, cnt);
            insn = BPF_MOV32_REG(dst, src);
            regStates[dst].type = regStates[src].type;
            printInsn("BPF_MOV32_REG", 0, dst, src, 0, 0);
            break;
        case 6:
            insn = BPF_MOV64_IMM(dst, imm64);
            regStates[dst].type = SCALAR_VALUE;
            printInsn("BPF_MOV64_IMM", 0, dst, 0, imm64, 0);
            break;
        case 7:
            insn = BPF_MOV32_IMM(dst, imm32);
            regStates[dst].type = SCALAR_VALUE;
            printInsn("BPF_MOV32_IMM", 0, dst, 0, imm32, 0);
            break;
        case 8:
            insn = BPF_NEG64_REG(dst);
            printInsn("BPF_NEG64_REG", 0, dst, 0, 0, 0);
            break;
        case 9:
            insn = BPF_NEG32_REG(dst);
            printInsn("BPF_NEG32_REG", 0, dst, 0, 0, 0);
            break;
    }

    updateByteCode(bpfBytecode, cnt, insn);
}

void genLSOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int maxMaps) {
    
    /*
        BPF_LDX_MEM(SIZE, DST, SRC, OFF)           dst_reg = *(uint *) (src_reg + off16)
        BPF_STX_MEM(SIZE, DST, SRC, OFF)           *(uint *) (dst_reg + off16) = src_reg
        BPF_ST_MEM(SIZE, DST, OFF, IMM)            *(uint *) (dst_reg + off16) = imm32
        BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)     
        BPF_LD_IMM64(DST, IMM) 2 insns

        BPF_LD_ABS(SIZE, IMM)                      R0 = *(uint *) (skb->data + imm32)
        BPF_LD_MAP_FD(DST, MAP_FD) 2 insns
    */

    int size = SIZE[rand() % sizeof(SIZE)];
    u_int8_t dst = regs[rand() % (sizeof(regs)-1)], src = regs[rand() % sizeof(regs)], op = 0;
    short int off = 0;
    int32_t imm32 = randNum32(), imm64 = randNum64(), fdIdx;
    struct bpf_insn insn = {0};
    bool newInsn = true;

    switch(rand() % 12) {
        case 0:
            if (!initRegPtr(src, Bit64, regStates, bpfBytecode, cnt)) return;
            insn = BPF_LDX_MEM(size, dst, src, off);
            printInsn("BPF_LDX_MEM", insn.code, dst, src, 0, off);
            break;
        case 1:
            // if (!initRegScalar(src, Bit64, regStates, bpfBytecode, cnt)) break;
            if (!initRegPtr(dst, Bit64, regStates, bpfBytecode, cnt)) return;
            insn = BPF_STX_MEM(size, dst, src, off);
            printInsn("BPF_STX_MEM", insn.code, dst, src, 0, off);
            break;
        case 2:
            if (!initRegPtr(dst, Bit64, regStates, bpfBytecode, cnt)) return;
            insn = BPF_ST_MEM(size, dst, off, imm32);
            printInsn("BPF_ST_MEM", insn.code, dst, 0, imm32, off);
            break;
        case 3:
            // TODO
            // if (!initRegScalar(src, Bit64, regStates, bpfBytecode, cnt)) break;
            if (!initRegPtr(dst, Bit64, regStates, bpfBytecode, cnt)) return;
            if (!BPF_ATOMIC_OP_Constrait(size, op, dst, src, off)) return;
            op = atomicOps[rand() % sizeof(atomicOps)];
            insn = BPF_ATOMIC_OP(size, op, dst, src, off);
            printInsn("BPF_ATOMIC_OP", insn.code, dst, src, 0, off);
            break;
        case 4: {
            struct bpf_insn insns1[2] = {
                BPF_LD_IMM64(dst, imm64),
            };
            updateByteCode(bpfBytecode, cnt, insns1[0]);
            insn = insns1[1];
            printInsn("BPF_LD_IMM64", insn.code, dst, 0, imm64, 0);
            break;
        } case 5:{
            fdIdx = (maxMaps == 0 ? -1 : rand() % maxMaps);
            struct bpf_insn insns2[2] = {
                BPF_LD_MAP_FD(dst, fdIdx),
            };
            updateByteCode(bpfBytecode, cnt, insns2[0]);
            insn = insns2[1];
            printInsn("BPF_LD_MAP_FD", insn.code, dst, 0, fdIdx, 0);
            break;
        } case 6:{
            return;
            // BPF_LD_FDIDX(DST, MAP_FDIDX)
            // break;
        } case 7:{
            fdIdx = (maxMaps == 0 ? -1 : rand() % maxMaps);
            struct bpf_insn insns4[2] = {
                BPF_LD_FD_MAPVALUE(dst, fdIdx, off),
            };
            updateByteCode(bpfBytecode, cnt, insns4[0]);
            insn = insns4[1];
            printInsn("BPF_LD_FD_MAPVALUE", insn.code, dst, 0, fdIdx, off);
            break;
        } case 8: {
            return;
            // BPF_LD_FDIDX_MAPVALUE(DST, FDIDX, OFF);
            // break;
        }
        case 9:
            insn = BPF_LD_PSEUDO_FUNC(dst, off);
            printInsn("BPF_LD_PSEUDO_FUNC", insn.code, dst, 0, 0, off);
            break;
        case 10:
            // Constrait: No DW
            insn = BPF_LD_ABS(size, imm32);
            printInsn("BPF_LD_ABS", insn.code, 0, 0, imm32, 0);
            break;
        case 11:
            // Constrait: No DW
            insn = BPF_LD_IND(size, imm32);
            printInsn("BPF_LD_IND", insn.code, 0, 0, imm32, 0);
            break;
    }
    
    updateByteCode(bpfBytecode, cnt, insn);
}

void genJMPOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    /*
        BPF_JMP_REG(OP, DST, SRC, OFF)
        BPF_JMP32_REG(OP, DST, SRC, OFF)
        BPF_JMP_IMM(OP, DST, IMM, OFF)
        BPF_JMP32_IMM(OP, DST, IMM, OFF)
    */

    u_int8_t dst = regs[rand() % (sizeof(regs)-1)],
             src = regs[rand() % sizeof(regs)],
             op = jmpops[rand() % sizeof(jmpops)];

    short int off = 0;
    int32_t imm32 = randNum32();
    int32_t imm64 = randNum64();
    struct bpf_insn insn;

    /*
    if (op == BPF_JA) {
        dst = 0;
        src = 0;
        imm32 = 0;
        imm64 = 0;
    }
    */

    switch(rand() % 4) {
        case 0:
            insn = BPF_JMP_REG(op, dst, src, off);
            printInsn("BPF_JMP_REG", op, dst, src, 0, off);
            break;
        case 1:
            insn = BPF_JMP32_REG(op, dst, src, off);
            printInsn("BPF_JMP32_REG", op, dst, src, 0, off);
            break;
        case 2:
            insn = BPF_JMP_IMM(op, dst, imm64, off);
            printInsn("BPF_JMP_IMM", op, dst, src, imm32, off);
            break;
        case 3:
            insn = BPF_JMP32_IMM(op, dst, imm32, off);
            printInsn("BPF_JMP32_IMM", op, dst, src, imm32, off);
            break;
        case 4:
            insn = BPF_JA_INSN(off);
            printInsn("BPF_JA_INSN", 0, 0, 0, 0, off);
            break;
    }

    updateByteCode(bpfBytecode, cnt, insn);
}

void genCallOP(struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    u_int32_t PCOFF = randNum32(), CALLIDX = randNum32();
    struct bpf_insn insn;

    switch(rand() % 2) {
        case 0:
            insn = BPF_HELPER_CALL(CALLIDX);
            printInsn("BPF_HELPER_CALL", 0, 0, 0, CALLIDX, 0);
            break;
        case 1:
            insn = BPF_CALL_PSEUDO_FUNC(PCOFF);
            printInsn("BPF_CALL_PSEUDO_FUNC", 0, 0, 0, 0, PCOFF);
            break;
        /*
        case 2:
            BPF_PSEUDO_KFUNC_CALL
            break;
        */
    }

    updateByteCode(bpfBytecode, cnt, insn);
}

int bpfAttrSize() {
    return sizeof(union bpf_attr);
}