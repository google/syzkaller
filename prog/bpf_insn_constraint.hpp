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