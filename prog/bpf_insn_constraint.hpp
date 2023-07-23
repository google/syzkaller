#define BPF_BASE_TYPE_MASK	255

/* ALU instruction constraits:
    1. Initialized
    2. Registers are all scalar value
    3. The number of shift bit should be less than 32/64
    4. Frame pointer is read only
*/
bool initRegScalar(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt, int64_t value) {
    
    // Constraint 4: R10 is read-only.
    if (reg == BPF_REG_10) return false;

    // The reg has already been initilized
    if (regStates[reg].type == SCALAR_VALUE &&
        regBit != Bit32Value && regBit != Bit64Value) {
        return true;
    }

    struct bpf_insn insn;
    int32_t imm32;
    int64_t imm64;
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
        case Bit32Value:
            insn = BPF_MOV32_IMM(reg, value);
            printInsn("BPF_MOV32_IMM", 0, reg, 0, value, 0);
            break;
        case Bit64Value:
            insn = BPF_MOV64_IMM(reg, value);
            printInsn("BPF_MOV64_IMM", 0, reg, 0, value, 0);
            break;
    }

    bool ret = updateByteCode(bpfBytecode, cnt, insn);
    if (ret) regStates[reg].type = SCALAR_VALUE;
    else return false;

    return true;
}

bool commonALUCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    u_int8_t bit = 0;

    switch (insn->code) {
        // NEG dst = ~dst
        case BPF_ALU | BPF_NEG:
        case BPF_ALU | BPF_END | BPF_TO_BE:
        case BPF_ALU | BPF_END | BPF_TO_LE:
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0)) return false;
            break;
        case BPF_ALU64 | BPF_NEG:
        case BPF_ALU64 | BPF_END | BPF_TO_BE:
        case BPF_ALU64 | BPF_END | BPF_TO_LE:
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0)) return false;
            break;
        // Shit
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_X:
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0)) return false;
            // Constraint 3: shifted bits <= 32/64
            if(!initRegScalar(insn->src_reg, Bit32Value, regStates, bpfBytecode, cnt, randRange(0, 32))) return false;
            break;
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
            if(!initRegScalar(insn->dst_reg, Bit32, regStates, bpfBytecode, cnt, 0)) return false;
            // Constraint 3: shifted bits <= 32/64
            insn->imm = randRange(0, 32);
            break;
        case BPF_ALU64 | BPF_LSH | BPF_X:
        case BPF_ALU64 | BPF_RSH | BPF_X:
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0)) return false;
            // Constraint 3: shifted bits <= 32/64
            if(!initRegScalar(insn->src_reg, Bit64Value, regStates, bpfBytecode, cnt, randRange(0, 64))) return false;
            break;
        case BPF_ALU64 | BPF_LSH | BPF_K:
        case BPF_ALU64 | BPF_RSH | BPF_K:
            if(!initRegScalar(insn->dst_reg, Bit64, regStates, bpfBytecode, cnt, 0)) return false;
            // Constraint 3: shifted bits <= 32/64
            insn->imm = randRange(0, 64);
            break;
        // Mov
        case BPF_ALU64 | BPF_MOV | BPF_X:
        case BPF_ALU | BPF_MOV | BPF_X:
            // R10 has already been initialized with stack ptr.
            if (insn->src_reg != BPF_REG_10) {
                bit = insn->code & BPF_ALU64 ? Bit64 : Bit32;
                if(!initRegScalar(insn->src_reg, bit, regStates, bpfBytecode, cnt, 0)) return false;
            }
            regStates[insn->dst_reg].type = regStates[insn->src_reg].type;
            break;
        case BPF_ALU64 | BPF_MOV | BPF_K:
        case BPF_ALU | BPF_MOV | BPF_K:
            // Constraint 4: r10 is read-only.
            if (insn->dst_reg == BPF_REG_10) return false;
            regStates[insn->dst_reg].type = SCALAR_VALUE;
            break;
        // Others
        default:
            bit = insn->code & BPF_ALU64 ? Bit64 : Bit32;
            if (insn->code & BPF_X) {
                // Registers
                if(!initRegScalar(insn->src_reg, bit, regStates, bpfBytecode, cnt, 0)) return false;
                if(!initRegScalar(insn->dst_reg, bit, regStates, bpfBytecode, cnt, 0)) return false;
            } else if ((insn->code & BPF_K) == 0) {
                if(!initRegScalar(insn->dst_reg, bit, regStates, bpfBytecode, cnt, 0)) return false;
            }
            break;
    }

    return true;
}


/* JMP instruction constraits:
    1. Initialized registers as any types.
    2. Offset: unsolved "unreachable insn" due to JA instruction.
*/

bool CommonInit(u_int8_t reg, u_int8_t regBit, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {
    
    if (regStates[reg].type != NOT_INIT) return true;

    struct bpf_insn insn;
    int32_t imm32;
    int64_t imm64;
    u_int8_t srcReg;

    // Randomly select one initialized register.
    int i = 0;
    while(true){
        if (regStates[i].type != NOT_INIT && (rand() % 100 > 50)){
            srcReg = i;
            break;
        }
        i = (i + 1) % sizeof(regs);
    }

    switch((rand() % 2 << 2) | regBit) {
        // Reg
        case Bit32:
            insn = BPF_MOV32_REG(reg, srcReg);
            regStates[reg].type = regStates[srcReg].type;
            break;
        case Bit64:
            insn = BPF_MOV64_REG(reg, srcReg);
            regStates[reg].type = regStates[srcReg].type;
            break;
        // Immediate
        case 1<<2 | Bit32:
            imm32 = randNum32();
            insn = BPF_MOV32_IMM(reg, imm32);
            regStates[reg].type = SCALAR_VALUE;
            break;
        case 1<<2 | Bit64:
            imm64 = randNum64();
            insn = BPF_MOV64_IMM(reg, imm64);
            regStates[reg].type = SCALAR_VALUE;
            break;
    }

    return updateByteCode(bpfBytecode, cnt, insn);
}


bool commonJMPCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    u_int8_t bit = insn->code & BPF_JMP ? Bit64 : Bit32;

    // JMP instruction doesn't require any constraints or initializations.
    if (insn->code == BPF_JA) return true;

    switch (insn->code & BPF_X) {
        case BPF_X:
            if(!CommonInit(insn->dst_reg, bit, regStates, bpfBytecode, cnt)) return false;
            if(!CommonInit(insn->src_reg, bit, regStates, bpfBytecode, cnt)) return false;
            break;
        default:
            if(!CommonInit(insn->dst_reg, bit, regStates, bpfBytecode, cnt)) return false;
            break;
    }
    
    insn->off = randRange(-*cnt, (NINSNS-*cnt-2));

    return true;
}

bool initRegPtr(u_int8_t reg, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {
    
    if (regStates[reg].type != NOT_INIT && regStates[reg].type != SCALAR_VALUE) return true;

    // Randomly select one initialized ptr register.
    int i = 0, loopTimes = 0;
    struct bpf_insn insn;
    while(loopTimes < 30){
        if (regStates[i].type != NOT_INIT && regStates[i].type != SCALAR_VALUE && (rand() % 100 > 50)){
            insn = BPF_MOV64_REG(reg, i);
            printInsn("BPF_MOV64_REG", 0, reg, i, 0, 0);
            updateByteCode(bpfBytecode, cnt, insn);
            regStates[reg].type = regStates[i].type; 
            return true;
        }
        i = (i + 1) % sizeof(regs);
        loopTimes ++;
    }

    return false;
}

// Load/Store instruction constraits:

inline bool isValidReg(int regno) {
    return regno < MAX_BPF_REG;	
}

bool isValidAtomicOp(struct bpf_insn *insn) {
    switch(insn->imm) {
        case BPF_ADD:
	    case BPF_ADD | BPF_FETCH:
	    case BPF_AND:
	    case BPF_AND | BPF_FETCH:
	    case BPF_OR:
	    case BPF_OR | BPF_FETCH:
	    case BPF_XOR:
	    case BPF_XOR | BPF_FETCH:
	    case BPF_XCHG:
	    case BPF_CMPXCHG:
            return true;
        default:
            return false;
    }
}

inline int base_type(int type)
{
	return type & BPF_BASE_TYPE_MASK;
}

bool isValidLdImmSrc(struct bpf_insn *insn) {
    switch(insn->src_reg) {
        case BPF_PSEUDO_MAP_VALUE:
        case BPF_PSEUDO_MAP_IDX_VALUE:
        case BPF_PSEUDO_MAP_FD:
        case BPF_PSEUDO_MAP_IDX:
            return true;
        default:
            return false;
    }
}

bool checkStAtomicType(int type) {
    switch (type) {
        case PTR_TO_CTX:
        case PTR_TO_PACKET:
        case PTR_TO_PACKET_META:
        case PTR_TO_FLOW_KEYS:
        case PTR_TO_SOCKET:
        case PTR_TO_SOCK_COMMON:
        case PTR_TO_TCP_SOCK:
        case PTR_TO_XDP_SOCK:
            return false;
        default:
            return true;
    }
}

inline bool stackOffCheck(regState *regStates, unsigned char reg, signed short off) {
    return (regStates[reg].type == PTR_TO_STACK && off < 0);
}

bool commonLSCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    switch(insn->code & ~BPF_SIZE(0xffffffff)) {
        // case BPF_ST_MEM: BPF_ST | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = imm32
        case BPF_ST | BPF_MEM:
            if (insn->src_reg != BPF_REG_0) return false;                                                   /* Constraint 1 */
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt)) return false;                      /* Constraint 2 */
            if (!stackOffCheck(regStates, insn->dst_reg, insn->off)) return false;                          /* Constraint 4 */
            if (regStates[insn->dst_reg].type == SCALAR_VALUE) return false;                                /* Constraint 5 */
            break;
        //case BPF_STX_MEM: BPF_STX | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = src
        case BPF_STX | BPF_MEM:
            if (!insn->imm != 0) return false;                                                              /* Constraint 1 */
            if (!(isValidReg(insn->src_reg) && isValidReg(insn->dst_reg))) return false;                    /* Constraint 2.1 */
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt)) return false;                      /* Constraint 2.2 */
            if (!initRegScalar(insn->src_reg, Bit64Value, regStates, bpfBytecode, cnt, 0)) return false;    /* Constraint 2.3 */
            break;
        //case BPF_ATOMIC_OP: BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC
        // *(u32 *)(dst + offset) += src
        case BPF_STX | BPF_ATOMIC:
            if (BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) return false;              /* Constraint 3.1 */
            if (!isValidAtomicOp(insn)) return false;                                                       /* Constraint 3.2 */
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt)) return false;                      /* Constraint 3.3 */
            if (!CommonInit(insn->src_reg, Bit64, regStates, bpfBytecode, cnt)) return false;               /* Constraint 3.3 */
            if (insn->imm == BPF_CMPXCHG && regStates[BPF_REG_0].type == PTR_TO_MAP_VALUE) return false;    /* Constraint 3.4 */
            if (regStates[insn->src_reg].type == PTR_TO_MAP_VALUE) return false;                            /* Constraint 3.5 */
            if (!checkStAtomicType(regStates[insn->dst_reg].type)) return false;                            /* Constraint 3.6 */
            if (!stackOffCheck(regStates, insn->src_reg, insn->off)) return false;                          /* Constraint 3.8 */
            if (!stackOffCheck(regStates, insn->dst_reg, insn->off)) return false;                          /* Constraint 3.8 */
            break;
        // case BPF_LDX_MEM: BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM
        // dst = *(size *) (src + offset)
        case BPF_LDX | BPF_MEM:
            if (!(isValidReg(insn->src_reg) && isValidReg(insn->dst_reg))) return false;                    /* Constraint 1 */
            if (!initRegPtr(insn->src_reg, regStates, bpfBytecode, cnt)) return false;                      /* Constraint 2, 4 */
            if (insn->dst_reg == BPF_REG_10) return false;                                                  /* Constraint 3 */
            if (regStates[insn->src_reg].type == SCALAR_VALUE) return false;                                /* Constraint 4 */
            if (!stackOffCheck(regStates, insn->src_reg, insn->off)) return false;                          /* Constraint 9 */
            regStates[insn->dst_reg].type = SCALAR_VALUE;
            break;
        // case BPF_LD_IMM64: BPF_LD | BPF_DW | BPF_IMM + src = 0
        // case BPF_LD_MAP_FD: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_FD
        // case BPF_LD_FD_MAPVALUE: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_VALUE
        // case BPF_LD_PSEUDO_FUNC: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_FUNC
        case BPF_LD | BPF_IMM:
            if (BPF_SIZE(insn->code) != BPF_DW) return false;                                               /* Constraint 2.1 */
            if (insn->off != 0) return false;                                                               /* Constraint 2.2 */
            if (insn->dst_reg == BPF_REG_10) return false;                                                  /* Constraint 2.3 */
            if (insn->src_reg == BPF_PSEUDO_BTF_ID) {                                                       /* Constraint 2.4 */
                struct regState dst = regStates[insn->dst_reg];
                if (base_type(dst.type) != PTR_TO_MEM && base_type(dst.type) != PTR_TO_BTF_ID)
                    return false;
            }
            if (!isValidLdImmSrc(insn)) return false;                                                       /* Constraint 2.5 */
            break;
        // case BPF_LD_ABS: BPF_LD | BPF_SIZE(SIZE) | BPF_ABS
        // case BPF_LD_IND: BPF_LD | BPF_SIZE(SIZE) | BPF_IND
        // R0 = *(uint *) (skb->data + imm32)
        case BPF_LD | BPF_ABS:
            if (insn->dst_reg != BPF_REG_0) return false;                                                   /* Constraint 3.1 */
            if (insn->off != 0) return false;                                                               /* Constraint 3.2 */
            if (BPF_SIZE(insn->code) == BPF_DW) return false;                                               /* Constraint 3.3 */
            if (regStates[BPF_REG_6].type != PTR_TO_CTX) return false;                                      /* Constraint 3.4 */
            if (insn->src_reg != BPF_REG_0) return false;                                                   /* Constraint 4 */
            regStates[BPF_REG_0].type = SCALAR_VALUE;
            break;
        case BPF_LD | BPF_IND:
            if (insn->dst_reg != BPF_REG_0) return false;                                                   /* Constraint 3.1 */
            if (insn->off != 0) return false;                                                               /* Constraint 3.2 */    
            if (BPF_SIZE(insn->code) == BPF_DW) return false;                                               /* Constraint 3.3 */
            if (regStates[BPF_REG_6].type != PTR_TO_CTX) return false;                                      /* Constraint 3.4 */
            if(!initRegPtr(insn->src_reg, regStates, bpfBytecode, cnt)) return false;                       /* Constraint 5 */
            regStates[BPF_REG_0].type = SCALAR_VALUE;
            break;
    }

    return true;
}