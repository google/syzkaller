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
        case Bit64:
            insn = BPF_MOV64_REG(reg, srcReg);
            regStates[reg].type = regStates[srcReg].type;
        // Immediate
        case 1<<2 | Bit32:
            imm32 = randNum32();
            insn = BPF_MOV32_IMM(reg, imm32);
            regStates[reg].type = SCALAR_VALUE;
        case 1<<2 | Bit64:
            imm64 = randNum64();
            insn = BPF_MOV64_IMM(reg, imm64);
            regStates[reg].type = SCALAR_VALUE;
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
            return true;
        }
        i = (i + 1) % sizeof(regs);
        loopTimes ++;
    }

    return false;
}

/* Load/Store instruction constraits:
    1. Initialized some registers as pointer, such as stack, map, context.
    2. Offset:
*/

bool commonLSCons(struct bpf_insn *insn, struct regState *regStates, struct bpf_insn *bpfBytecode, int *cnt) {

    switch(insn->code & ~BPF_SIZE(0xffffffff)) {
        // case BPF_ST_MEM: BPF_ST | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = imm32
        case BPF_ST | BPF_MEM:
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt)) return false;
            break;
        //case BPF_STX_MEM: BPF_STX | BPF_SIZE(SIZE) | BPF_MEM
        // *(size *) (dst + offset) = src
        //case BPF_ATOMIC_OP: BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC
        // *(u32 *)(dst + offset) += src
        case BPF_STX | BPF_ATOMIC:
            if (!initRegPtr(insn->dst_reg, regStates, bpfBytecode, cnt)) return false;
            // TODO BIT
            if (!CommonInit(insn->src_reg, Bit64, regStates, bpfBytecode, cnt)) return false;
            break;
        // case BPF_LDX_MEM: BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM
        // dst = *(size *) (src + offset)
        case BPF_LDX | BPF_MEM:
            if (!initRegPtr(insn->src_reg, regStates, bpfBytecode, cnt)) return false;
            break;
        // case BPF_LD_IMM64: BPF_LD | BPF_DW | BPF_IMM + src = 0
        // case BPF_LD_MAP_FD: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_FD
        // case BPF_LD_FD_MAPVALUE: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_MAP_VALUE
        // case BPF_LD_PSEUDO_FUNC: BPF_LD | BPF_DW | BPF_IMM + src = BPF_PSEUDO_FUNC
        case BPF_LD | BPF_IMM:
            break;
        // case BPF_LD_ABS: BPF_LD | BPF_SIZE(SIZE) | BPF_ABS
        // case BPF_LD_IND: BPF_LD | BPF_SIZE(SIZE) | BPF_IND
        // R0 = *(uint *) (skb->data + imm32)
        case BPF_LD | BPF_ABS:
        case BPF_LD | BPF_IND:
            // r1 = ctx;
            break;
    }

    return true;
}