/*
 * vm_heavy.cpp — Heavy VM stress-test for wxtrace.
 *
 * A register+stack VM with ~25 opcodes, function calls, heap memory,
 * and JNI callbacks woven into the execution. Designed to produce
 * tens of thousands of basic blocks for pressure testing the trace pipeline.
 */

#include <jni.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <android/log.h>
#include <time.h>

#define LOG_TAG "wxtrace-demo"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ============================================================
 * Opcode encoding (1 byte, some take 1-2 byte operand)
 * ============================================================ */
enum Op : uint8_t {
    OP_HALT = 0,
    /* Stack */
    OP_PUSH,        // PUSH imm32 (4 bytes LE)
    OP_POP,
    OP_DUP,
    OP_SWAP,
    OP_ROT,         // rotate top 3
    /* Arithmetic */
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    /* Bitwise */
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_SHL,
    OP_SHR,
    /* Comparison (push 0 or 1) */
    OP_EQ,
    OP_GT,
    OP_LT,
    /* Control flow */
    OP_JMP,         // JMP target16 (2 bytes LE)
    OP_JZ,          // JZ  target16
    OP_JNZ,         // JNZ target16
    OP_CALL,        // CALL target16 (push return addr, jump)
    OP_RET,         // RET (pop return addr, jump back)
    /* Register access */
    OP_LOADR,       // LOADR slot1 — push reg[slot]
    OP_STORER,      // STORER slot1 — pop into reg[slot]
    /* Memory (heap) */
    OP_LOADH,       // LOADH — pop addr, push heap[addr]
    OP_STOREH,      // STOREH — pop value then addr, heap[addr] = value
    /* JNI */
    OP_JNI_CALL,    // JNI_CALL fn_index1 — call Java method, push result
    OP_JNI_STR,     // JNI_STR index1 — push ptr to string from Java
    NUM_OPS
};

/* ============================================================
 * VM state
 * ============================================================ */
static constexpr int REG_COUNT  = 64;
static constexpr int STACK_SIZE = 256;
static constexpr int HEAP_SIZE  = 1024;   /* 1024 × 8 bytes = 8KB heap */
static constexpr int CALL_DEPTH = 32;

struct HeavyVM {
    int64_t  regs[REG_COUNT];
    int64_t  stack[STACK_SIZE];
    int64_t  heap[HEAP_SIZE];
    int      sp;
    int      pc;
    int      call_stack[CALL_DEPTH];
    int      call_sp;
    int64_t  steps;
    int64_t  max_steps;

    /* JNI callback context */
    JNIEnv  *env;
    jobject  callback_obj;   /* Java object with @CalledByNative methods */
    jmethodID mid_callback;
    jmethodID mid_get_string;
    jmethodID mid_log;
    jmethodID mid_base64;    /* vmBase64Encode(long) → String */
};

/* ============================================================
 * Bytecode builder helper
 * ============================================================ */
class BytecodeBuilder {
public:
    std::vector<uint8_t> code;

    int pos() const { return (int)code.size(); }

    void emit(Op op) { code.push_back((uint8_t)op); }

    void emit_u8(uint8_t v) { code.push_back(v); }

    void emit_i32(int32_t v) {
        code.push_back((uint8_t)(v));
        code.push_back((uint8_t)(v >> 8));
        code.push_back((uint8_t)(v >> 16));
        code.push_back((uint8_t)(v >> 24));
    }

    void emit_u16(uint16_t v) {
        code.push_back((uint8_t)(v));
        code.push_back((uint8_t)(v >> 8));
    }

    void emit_push(int32_t imm) { emit(OP_PUSH); emit_i32(imm); }
    void emit_jmp(int target)   { emit(OP_JMP); emit_u16((uint16_t)target); }
    void emit_jz(int target)    { emit(OP_JZ);  emit_u16((uint16_t)target); }
    void emit_jnz(int target)   { emit(OP_JNZ); emit_u16((uint16_t)target); }
    void emit_call(int target)  { emit(OP_CALL); emit_u16((uint16_t)target); }
    void emit_ret()             { emit(OP_RET); }
    void emit_pop()             { emit(OP_POP); }
    void emit_loadr(int slot)   { emit(OP_LOADR); emit_u8((uint8_t)slot); }
    void emit_storer(int slot)  { emit(OP_STORER); emit_u8((uint8_t)slot); }
    void emit_jni_call(int fn)  { emit(OP_JNI_CALL); emit_u8((uint8_t)fn); }
    void emit_jni_str(int idx)  { emit(OP_JNI_STR); emit_u8((uint8_t)idx); }
    void emit_halt()            { emit(OP_HALT); }
};

/* ============================================================
 * JNI callback helpers
 * ============================================================ */

enum JniFn : uint8_t {
    JNI_FN_CALLBACK = 0,   // vmCallback(opcode, arg1, arg2) → int
    JNI_FN_GET_STRING,     // vmGetString(index) → String
    JNI_FN_LOG,            // vmLog(String)
    JNI_FN_BASE64,         // vmBase64Encode(long) → String (base64 of hex)
    JNI_FN_COUNT
};

static int64_t vm_jni_dispatch(HeavyVM &vm, int fn_index, int64_t arg1, int64_t arg2) {
    if (!vm.env || !vm.callback_obj) return 0;

    switch ((JniFn)fn_index) {
    case JNI_FN_CALLBACK:
        if (vm.mid_callback)
            return vm.env->CallIntMethod(vm.callback_obj, vm.mid_callback,
                                         (jint)0, (jint)arg1, (jint)arg2);
        break;
    case JNI_FN_GET_STRING:
        if (vm.mid_get_string) {
            jstring js = (jstring)vm.env->CallObjectMethod(vm.callback_obj,
                                                            vm.mid_get_string, (jint)arg1);
            if (js) {
                const char *p = vm.env->GetStringUTFChars(js, nullptr);
                int64_t val = p ? (int64_t)(unsigned char)p[0] : 0;
                if (p) vm.env->ReleaseStringUTFChars(js, p);
                vm.env->DeleteLocalRef(js);
                return val;
            }
        }
        break;
    case JNI_FN_LOG:
        if (vm.mid_log) {
            jstring js = vm.env->NewStringUTF("vm_heavy log");
            if (js) {
                vm.env->CallVoidMethod(vm.callback_obj, vm.mid_log, js);
                vm.env->DeleteLocalRef(js);
            }
        }
        break;
    case JNI_FN_BASE64:
        if (vm.mid_base64) {
            jstring js = (jstring)vm.env->CallObjectMethod(vm.callback_obj,
                                                            vm.mid_base64, (jlong)arg1);
            if (js) {
                const char *p = vm.env->GetStringUTFChars(js, nullptr);
                int64_t val = p ? (int64_t)(unsigned char)p[0] : 0;
                if (p) vm.env->ReleaseStringUTFChars(js, p);
                vm.env->DeleteLocalRef(js);
                return val;
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

/* ============================================================
 * VM fetch/execute
 * ============================================================ */
static inline int64_t fetch_i32(const uint8_t *prog, int &pc) {
    int32_t v = (int32_t)((uint32_t)prog[pc] | ((uint32_t)prog[pc+1] << 8) |
                           ((uint32_t)prog[pc+2] << 16) | ((uint32_t)prog[pc+3] << 24));
    pc += 4;
    return (int64_t)v;
}

static inline uint16_t fetch_u16(const uint8_t *prog, int &pc) {
    uint16_t v = (uint16_t)(prog[pc] | ((uint16_t)prog[pc+1] << 8));
    pc += 2;
    return v;
}

static inline uint8_t fetch_u8(const uint8_t *prog, int &pc) {
    return prog[pc++];
}

/* Non-static so its address can be exported for trace range targeting. */
int64_t vm_heavy_run(HeavyVM &vm, const uint8_t *prog, int prog_len) {
    auto &sp = vm.sp;
    auto &pc = vm.pc;
    auto *stk = vm.stack;
    auto *regs = vm.regs;
    auto *heap = vm.heap;

    while (pc >= 0 && pc < prog_len && vm.steps++ < vm.max_steps) {
        uint8_t op = fetch_u8(prog, pc);

        switch (op) {
        case OP_HALT:
            goto done;

        /* ---- Stack ---- */
        case OP_PUSH:
            stk[sp++] = fetch_i32(prog, pc);
            break;
        case OP_POP:
            sp--;
            break;
        case OP_DUP:
            stk[sp] = stk[sp - 1];
            sp++;
            break;
        case OP_SWAP: {
            int64_t t = stk[sp - 1];
            stk[sp - 1] = stk[sp - 2];
            stk[sp - 2] = t;
            break;
        }
        case OP_ROT: {
            int64_t t = stk[sp - 3];
            stk[sp - 3] = stk[sp - 2];
            stk[sp - 2] = stk[sp - 1];
            stk[sp - 1] = t;
            break;
        }

        /* ---- Arithmetic ---- */
        case OP_ADD: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a + b; break; }
        case OP_SUB: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a - b; break; }
        case OP_MUL: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a * b; break; }
        case OP_DIV: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = b ? a / b : 0; break; }
        case OP_MOD: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = b ? a % b : 0; break; }

        /* ---- Bitwise ---- */
        case OP_AND: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a & b; break; }
        case OP_OR:  { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a | b; break; }
        case OP_XOR: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a ^ b; break; }
        case OP_SHL: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = a << (b & 63); break; }
        case OP_SHR: { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = (int64_t)((uint64_t)a >> (b & 63)); break; }

        /* ---- Comparison ---- */
        case OP_EQ:  { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = (a == b) ? 1 : 0; break; }
        case OP_GT:  { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = (a > b)  ? 1 : 0; break; }
        case OP_LT:  { int64_t b = stk[--sp], a = stk[--sp]; stk[sp++] = (a < b)  ? 1 : 0; break; }

        /* ---- Control flow ---- */
        case OP_JMP:
            pc = fetch_u16(prog, pc);
            break;
        case OP_JZ: {
            uint16_t target = fetch_u16(prog, pc);
            if (stk[--sp] == 0) pc = target;
            break;
        }
        case OP_JNZ: {
            uint16_t target = fetch_u16(prog, pc);
            if (stk[--sp] != 0) pc = target;
            break;
        }
        case OP_CALL: {
            uint16_t target = fetch_u16(prog, pc);
            if (vm.call_sp < CALL_DEPTH)
                vm.call_stack[vm.call_sp++] = pc;
            pc = target;
            break;
        }
        case OP_RET:
            if (vm.call_sp > 0)
                pc = vm.call_stack[--vm.call_sp];
            else
                goto done;
            break;

        /* ---- Registers ---- */
        case OP_LOADR: {
            uint8_t slot = fetch_u8(prog, pc);
            stk[sp++] = regs[slot & (REG_COUNT - 1)];
            break;
        }
        case OP_STORER: {
            uint8_t slot = fetch_u8(prog, pc);
            regs[slot & (REG_COUNT - 1)] = stk[--sp];
            break;
        }

        /* ---- Heap ---- */
        case OP_LOADH: {
            int64_t addr = stk[--sp];
            if (addr >= 0 && addr < HEAP_SIZE)
                stk[sp++] = heap[addr];
            else
                stk[sp++] = 0;
            break;
        }
        case OP_STOREH: {
            int64_t val  = stk[--sp];
            int64_t addr = stk[--sp];
            if (addr >= 0 && addr < HEAP_SIZE)
                heap[addr] = val;
            break;
        }

        /* ---- JNI ---- */
        case OP_JNI_CALL: {
            uint8_t fn = fetch_u8(prog, pc);
            int64_t arg2 = stk[--sp];
            int64_t arg1 = stk[--sp];
            stk[sp++] = vm_jni_dispatch(vm, fn, arg1, arg2);
            break;
        }
        case OP_JNI_STR: {
            uint8_t idx = fetch_u8(prog, pc);
            stk[sp++] = vm_jni_dispatch(vm, JNI_FN_GET_STRING, idx, 0);
            break;
        }

        default:
            goto done;
        }

        /* Bounds check */
        if (sp < 1) sp = 1;
        if (sp >= STACK_SIZE - 1) sp = STACK_SIZE - 2;
    }

done:
    return sp > 0 ? stk[sp - 1] : 0;
}

/* ============================================================
 * Program builder — a complex multi-function program
 *
 * Functions:
 *   0: fib(n)        — recursive fibonacci
 *   1: hash(buf,n)   — hash a buffer (uses heap)
 *   2: bubble_sort(n) — sort heap[0..n] in place
 *   3: main(arg)      — orchestrator, calls the above + JNI
 *
 * This produces ~50K-100K basic blocks for arg=1000.
 * ============================================================ */
static int build_stress_program(BytecodeBuilder &b, int arg) {
    /* We'll patch jump targets after building. Use placeholder 0xFFFF. */
    auto patch_pos = [&](int fixup_at, int target) {
        b.code[fixup_at]     = (uint8_t)(target);
        b.code[fixup_at + 1] = (uint8_t)(target >> 8);
    };

    /*
     * func_fib: R0=n → R1=result
     * Uses registers: R0=input, R1=result, R2=temp
     */
    int func_fib = b.pos();
    {
        b.emit_loadr(0);           // push n
        b.emit_push(2);
        b.emit(OP_LT);             // n < 2?
        int patch_base = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF); // → not base case

        /* base case: return n */
        b.emit_loadr(0);
        b.emit_storer(1);          // R1 = n
        b.emit_ret();

        /* recursive case: fib(n-1) + fib(n-2) */
        patch_pos(patch_base + 1, b.pos());

        /* save n, compute fib(n-1) */
        b.emit_loadr(0); b.emit_storer(2);  // R2 = n (save)

        b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB); b.emit_storer(0); // R0 = n-1
        b.emit_call(func_fib);               // fib(n-1) → R1
        b.emit_loadr(1); b.emit_storer(3);   // R3 = fib(n-1)

        /* compute fib(n-2) */
        b.emit_loadr(2); b.emit_push(2); b.emit(OP_SUB); b.emit_storer(0); // R0 = n-2
        b.emit_call(func_fib);               // fib(n-2) → R1

        /* result = fib(n-1) + fib(n-2) */
        b.emit_loadr(3); b.emit_loadr(1); b.emit(OP_ADD); b.emit_storer(1);
        b.emit_ret();
    }

    /*
     * func_hash: compute a simple hash of heap[0..R0-1] → R1
     * Uses: R0=count, R1=accumulator, R2=index, R3=temp
     */
    int func_hash = b.pos();
    {
        b.emit_push(0x811c9dc5); b.emit_storer(1);  // R1 = FNV offset basis
        b.emit_push(0); b.emit_storer(2);             // R2 = 0 (index)

        int loop_start = b.pos();
        /* check: index < count? */
        b.emit_loadr(2); b.emit_loadr(0); b.emit(OP_LT);
        int patch_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);  // → done

        /* hash = hash * 0x01000193 ^ heap[index] */
        b.emit_loadr(1); b.emit_push(0x01000193); b.emit(OP_MUL);
        b.emit_loadr(2); b.emit(OP_LOADH);  // heap[R2]
        b.emit(OP_XOR); b.emit_storer(1);

        /* index++ */
        b.emit_loadr(2); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(2);

        b.emit_jmp(loop_start);

        patch_pos(patch_end + 1, b.pos());
        b.emit_ret();
    }

    /*
     * func_sort: bubble sort heap[0..R0-1]
     * Uses: R0=size, R1=i, R2=j, R3=temp_a, R4=temp_b
     */
    int func_sort = b.pos();
    {
        b.emit_push(0); b.emit_storer(1);  // i = 0

        int outer_cond = b.pos();
        b.emit_loadr(1); b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB); b.emit(OP_LT);
        int patch_outer_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        b.emit_push(0); b.emit_storer(2);  // j = 0

        int inner_cond = b.pos();
        /* j < (size - 1 - i) */
        b.emit_loadr(2); b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB);
        b.emit_loadr(1); b.emit(OP_SUB); b.emit(OP_LT);
        int patch_inner_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        /* load heap[j] and heap[j+1] */
        b.emit_loadr(2); b.emit(OP_LOADH); b.emit_storer(3);  // a = heap[j]
        b.emit_loadr(2); b.emit_push(1); b.emit(OP_ADD);
        b.emit(OP_LOADH); b.emit_storer(4);                     // b = heap[j+1]

        /* if a > b: swap */
        b.emit_loadr(3); b.emit_loadr(4); b.emit(OP_GT);
        int patch_no_swap = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        /* swap: heap[j] = b, heap[j+1] = a */
        b.emit_loadr(2); b.emit_loadr(4); b.emit(OP_STOREH);
        b.emit_loadr(2); b.emit_push(1); b.emit(OP_ADD);
        b.emit_loadr(3); b.emit(OP_STOREH);

        patch_pos(patch_no_swap + 1, b.pos());

        /* j++ */
        b.emit_loadr(2); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(2);
        b.emit_jmp(inner_cond);

        patch_pos(patch_inner_end + 1, b.pos());

        /* i++ */
        b.emit_loadr(1); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(1);
        b.emit_jmp(outer_cond);

        patch_pos(patch_outer_end + 1, b.pos());
        b.emit_ret();
    }

    /*
     * func_main: orchestrator
     *   1. Fill heap[0..arg] with pseudo-random data
     *   2. Call JNI callbacks (FindClass, NewStringUTF, etc.)
     *   3. Call hash
     *   4. Call sort
     *   5. Call hash again (verify sorted)
     *   6. JNI log result
     */
    int func_main = b.pos();
    {
        /* Fill heap with pseudo-random data: heap[i] = (i * 2654435761) >> 16 */
        b.emit_push(0); b.emit_storer(2);  // i = 0
        int fill_loop = b.pos();
        b.emit_loadr(2); b.emit_loadr(0); b.emit(OP_LT);
        int patch_fill_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        b.emit_loadr(2);                       // addr = i
        b.emit_loadr(2); b.emit_push(2654435761u & 0x7FFFFFFF); b.emit(OP_MUL);
        b.emit_push(16); b.emit(OP_SHR);       // val = (i * c) >> 16
        b.emit(OP_STOREH);                      // heap[i] = val

        b.emit_loadr(2); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(2);
        b.emit_jmp(fill_loop);
        patch_pos(patch_fill_end + 1, b.pos());

        /* JNI: callback(0, arg, 0) */
        b.emit_push(0); b.emit_loadr(0); b.emit_push(0);
        b.emit_jni_call(JNI_FN_CALLBACK);
        b.emit_pop();

        /* JNI: getString(0) — get a string from Java */
        b.emit_push(0); b.emit_jni_str(0);
        b.emit_pop();

        /* JNI: getString(1) */
        b.emit_push(1); b.emit_jni_str(1);
        b.emit_pop();

        /* Hash before sort */
        b.emit_loadr(0); b.emit_call(func_hash);
        b.emit_loadr(1); b.emit_storer(5);  // R5 = hash_before

        /* Sort */
        b.emit_loadr(0); b.emit_call(func_sort);

        /* Hash after sort */
        b.emit_loadr(0); b.emit_call(func_hash);
        b.emit_loadr(1); b.emit_storer(6);  // R6 = hash_after

        /* JNI: callback(1, hash_before, hash_after) */
        b.emit_push(1); b.emit_loadr(5); b.emit_loadr(6);
        b.emit_jni_call(JNI_FN_CALLBACK);
        b.emit_pop();

        /* JNI: log result */
        b.emit_push(0); b.emit_jni_call(JNI_FN_LOG);

        /* Fibonacci on a small value (cap at 10 to avoid explosion) */
        b.emit_loadr(0); b.emit_push(100); b.emit(OP_GT);
        int patch_fib_cap = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);
        b.emit_push(10); b.emit_storer(0);  // cap at 10
        patch_pos(patch_fib_cap + 1, b.pos());

        /* if arg < 2, use 2 */
        b.emit_loadr(0); b.emit_push(2); b.emit(OP_LT);
        int patch_fib_min = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);
        b.emit_push(2); b.emit_storer(0);
        patch_pos(patch_fib_min + 1, b.pos());

        b.emit_loadr(0); b.emit_call(func_fib);
        b.emit_loadr(1); b.emit_storer(7);  // R7 = fib_result

        /* Final JNI callback with fib result */
        b.emit_push(2); b.emit_loadr(7); b.emit_push(0);
        b.emit_jni_call(JNI_FN_CALLBACK);
        b.emit_pop();

        /* Return combined result */
        b.emit_loadr(5); b.emit_loadr(6); b.emit(OP_ADD);
        b.emit_loadr(7); b.emit(OP_ADD);
        b.emit_storer(1);
        b.emit_ret();
    }

    /* Entry point: call func_main(arg) */
    int entry = b.pos();
    b.emit_push(arg); b.emit_storer(0);  // R0 = arg
    b.emit_call(func_main);
    b.emit_loadr(1);                      // push result
    b.emit_halt();

    return entry;  /* caller must start VM at this PC */
}

/* ============================================================
 * XXTEA bytecode program — modified XXTEA encryption on HeavyVM
 *
 * Register allocation:
 *   R0  = n (number of uint32_t words in data)
 *   R1  = sum
 *   R2  = z
 *   R3  = y
 *   R4  = p (outer loop counter)
 *   R5  = e = (sum >> 2) & 3
 *   R6  = q (inner loop counter)
 *   R7  = temp
 *   R8  = rounds = 6 + 52/n
 *   R9  = temp2
 *   R10 = key[0] = 0xdeadbeef
 *   R11 = key[1] = 0xcafebabe
 *   R12 = key[2] = 0x12345678
 *   R13 = key[3] = 0x9abcdef0
 *   R14 = DELTA = 0x9e3779b9
 *   R15 = result accumulator (checksum of ciphertext)
 *   R16 = MX result
 *
 * Heap layout:
 *   heap[0..n-1] = v[] (plaintext → ciphertext in-place)
 *
 * MX macro (stack computation):
 *   push z; push 7; SHR          → (z >> 7)
 *   push y; push 3; SHL          → (y << 3)
 *   XOR                           → (z>>7) ^ (y<<3)
 *   push y; push 5; SHR          → (y >> 5)
 *   push z; push 6; SHL          → (z << 6)
 *   XOR                           → (y>>5) ^ (z<<6)
 *   ADD                           → ((z>>7)^(y<<3)) + ((y>>5)^(z<<6))
 *   push sum; push y; XOR        → sum ^ y
 *   push key[(p&3)^e]; push z; XOR → key[...] ^ z
 *   ADD                           → (sum^y) + (key[...]^z)
 *   XOR                           → final MX
 * ============================================================ */
static int build_xxtea_program(BytecodeBuilder &b, int n_words) {
    auto patch_pos = [&](int fixup_at, int target) {
        b.code[fixup_at]     = (uint8_t)(target);
        b.code[fixup_at + 1] = (uint8_t)(target >> 8);
    };

    /* ---- Helper: emit MX macro (consumes nothing, pushes result) ---- */
    /* On entry: R2=z, R3=y, R1=sum, R4=p, R5=e, R10-R13=key */
    auto emit_mx = [&]() {
        /* ((z >> 7) ^ (y << 3)) */
        b.emit_loadr(2); b.emit_push(7); b.emit(OP_SHR);   // z>>7
        b.emit_loadr(3); b.emit_push(3); b.emit(OP_SHL);   // y<<3
        b.emit(OP_XOR);                                      // (z>>7)^(y<<3)

        /* + ((y >> 5) ^ (z << 6)) */
        b.emit_loadr(3); b.emit_push(5); b.emit(OP_SHR);   // y>>5
        b.emit_loadr(2); b.emit_push(6); b.emit(OP_SHL);   // z<<6
        b.emit(OP_XOR);                                      // (y>>5)^(z<<6)
        b.emit(OP_ADD);                                      // part1

        /* ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)) */
        b.emit_loadr(1); b.emit_loadr(3); b.emit(OP_XOR);  // sum^y

        /* key[(p & 3) ^ e] */
        b.emit_loadr(4); b.emit_push(3); b.emit(OP_AND);   // p&3
        b.emit_loadr(5); b.emit(OP_XOR);                    // (p&3)^e
        /* dispatch key index: 0→R10, 1→R11, 2→R12, 3→R13 */
        b.emit(OP_DUP); b.emit_push(0); b.emit(OP_EQ);
        int patch_k1 = b.pos(); b.emit(OP_JZ); b.emit_u16(0xFFFF);
        b.emit_pop(); b.emit_loadr(10);
        int jmp_k0 = b.pos(); b.emit(OP_JMP); b.emit_u16(0xFFFF);
        patch_pos(patch_k1 + 1, b.pos());
        b.emit(OP_DUP); b.emit_push(1); b.emit(OP_EQ);
        int patch_k2 = b.pos(); b.emit(OP_JZ); b.emit_u16(0xFFFF);
        b.emit_pop(); b.emit_loadr(11);
        int jmp_k1 = b.pos(); b.emit(OP_JMP); b.emit_u16(0xFFFF);
        patch_pos(patch_k2 + 1, b.pos());
        b.emit(OP_DUP); b.emit_push(2); b.emit(OP_EQ);
        int patch_k3 = b.pos(); b.emit(OP_JZ); b.emit_u16(0xFFFF);
        b.emit_pop(); b.emit_loadr(12);
        int jmp_k2 = b.pos(); b.emit(OP_JMP); b.emit_u16(0xFFFF);
        patch_pos(patch_k3 + 1, b.pos());
        b.emit_pop(); b.emit_loadr(13);  /* default: key[3] */
        int dispatch_end = b.pos();
        /* Patch all key-dispatch JMPs to the common exit */
        patch_pos(jmp_k0 + 1, dispatch_end);
        patch_pos(jmp_k1 + 1, dispatch_end);
        patch_pos(jmp_k2 + 1, dispatch_end);

        b.emit_loadr(2); b.emit(OP_XOR);                    // key[...]^z
        b.emit(OP_ADD);                                      // (sum^y)+(key[...]^z)
        b.emit(OP_XOR);                                      // final MX
    };

    /* ---- func_xxtea_encrypt: encrypt heap[0..R0-1] in place ---- */
    int func_xxtea = b.pos();
    {
        /* Initialize: rounds = 6 + 52/n */
        b.emit_push(52); b.emit_loadr(0); b.emit(OP_DIV);
        b.emit_push(6); b.emit(OP_ADD); b.emit_storer(8);   // R8 = rounds

        /* sum = 0, z = v[n-1] */
        b.emit_push(0); b.emit_storer(1);                   // sum = 0
        b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB);
        b.emit(OP_LOADH); b.emit_storer(2);                 // z = heap[n-1]

        /* Outer loop: p = 0..rounds-1 */
        b.emit_push(0); b.emit_storer(4);                   // p = 0

        int outer_cond = b.pos();
        b.emit_loadr(4); b.emit_loadr(8); b.emit(OP_LT);
        int patch_outer_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        /* sum += DELTA */
        b.emit_loadr(1); b.emit_loadr(14); b.emit(OP_ADD); b.emit_storer(1);

        /* e = (sum >> 2) & 3 */
        b.emit_loadr(1); b.emit_push(2); b.emit(OP_SHR);
        b.emit_push(3); b.emit(OP_AND); b.emit_storer(5);

        /* Inner loop: q = 0..n-2 */
        b.emit_push(0); b.emit_storer(6);

        int inner_cond = b.pos();
        b.emit_loadr(6); b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB); b.emit(OP_LT);
        int patch_inner_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        /* y = v[q+1] */
        b.emit_loadr(6); b.emit_push(1); b.emit(OP_ADD);
        b.emit(OP_LOADH); b.emit_storer(3);                 // y = heap[q+1]

        /* v[q] += MX */
        emit_mx();                                           // MX on stack
        b.emit_loadr(6); b.emit(OP_LOADH);                  // heap[q]
        b.emit(OP_ADD);                                      // heap[q] + MX
        b.emit_loadr(6); b.emit(OP_SWAP); b.emit(OP_STOREH); // heap[q] = result

        /* z = v[q] */
        b.emit_loadr(6); b.emit(OP_LOADH); b.emit_storer(2);

        /* q++ */
        b.emit_loadr(6); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(6);
        b.emit_jmp(inner_cond);

        patch_pos(patch_inner_end + 1, b.pos());

        /* y = v[0] */
        b.emit_push(0); b.emit(OP_LOADH); b.emit_storer(3);

        /* v[n-1] += MX */
        emit_mx();
        b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB);
        b.emit(OP_LOADH); b.emit(OP_ADD);
        b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB);
        b.emit(OP_SWAP); b.emit(OP_STOREH);

        /* z = v[n-1] */
        b.emit_loadr(0); b.emit_push(1); b.emit(OP_SUB);
        b.emit(OP_LOADH); b.emit_storer(2);

        /* p++ */
        b.emit_loadr(4); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(4);
        b.emit_jmp(outer_cond);

        patch_pos(patch_outer_end + 1, b.pos());
        b.emit_ret();
    }

    /* ---- func_hex_encode: compute checksum of heap[0..R0-1] → R15 ---- */
    int func_checksum = b.pos();
    {
        b.emit_push(0); b.emit_storer(15);  // checksum = 0
        b.emit_push(0); b.emit_storer(6);   // i = 0

        int cs_loop = b.pos();
        b.emit_loadr(6); b.emit_loadr(0); b.emit(OP_LT);
        int patch_cs_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        /* checksum ^= heap[i] * (i+1) */
        b.emit_loadr(6); b.emit(OP_LOADH);
        b.emit_loadr(6); b.emit_push(1); b.emit(OP_ADD);
        b.emit(OP_MUL);
        b.emit_loadr(15); b.emit(OP_XOR); b.emit_storer(15);

        b.emit_loadr(6); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(6);
        b.emit_jmp(cs_loop);

        patch_pos(patch_cs_end + 1, b.pos());
        b.emit_ret();
    }

    /* ---- func_main: orchestrator ---- */
    int func_main_xxtea = b.pos();
    {
        /* Initialize key in registers */
        b.emit_push((int32_t)0xdeadbeef); b.emit_storer(10);  // key[0]
        b.emit_push((int32_t)0xcafebabe); b.emit_storer(11);  // key[1]
        b.emit_push((int32_t)0x12345678); b.emit_storer(12);  // key[2]
        b.emit_push((int32_t)0x9abcdef0); b.emit_storer(13);  // key[3]
        b.emit_push((int32_t)0x9e3779b9); b.emit_storer(14);  // DELTA

        /* Fill heap with pseudo-random data (plaintext) */
        /* heap[i] = (i * 2654435761) >> 16 */
        b.emit_push(0); b.emit_storer(6);  // i = 0
        int fill_loop = b.pos();
        b.emit_loadr(6); b.emit_loadr(0); b.emit(OP_LT);
        int patch_fill_end = b.pos();
        b.emit(OP_JZ); b.emit_u16(0xFFFF);

        b.emit_loadr(6);                       // addr = i
        b.emit_loadr(6); b.emit_push(2654435761u & 0x7FFFFFFF); b.emit(OP_MUL);
        b.emit_push(16); b.emit(OP_SHR);       // val = (i * c) >> 16
        b.emit(OP_STOREH);                      // heap[i] = val

        b.emit_loadr(6); b.emit_push(1); b.emit(OP_ADD); b.emit_storer(6);
        b.emit_jmp(fill_loop);
        patch_pos(patch_fill_end + 1, b.pos());

        /* Encrypt: call func_xxtea */
        b.emit_call(func_xxtea);

        /* Compute checksum of ciphertext */
        b.emit_loadr(0); b.emit_call(func_checksum);

        /* JNI: base64Encode(checksum) — triggers Java Base64 encoding */
        b.emit_loadr(15); b.emit_push(0);
        b.emit_jni_call(JNI_FN_BASE64);
        b.emit_pop();

        /* JNI: callback(0, checksum, n) */
        b.emit_push(0); b.emit_loadr(15); b.emit_loadr(0);
        b.emit_jni_call(JNI_FN_CALLBACK);
        b.emit_pop();

        /* Return checksum */
        b.emit_loadr(15); b.emit_storer(1);
        b.emit_ret();
    }

    /* Entry point */
    int entry = b.pos();
    b.emit_push(n_words); b.emit_storer(0);  // R0 = n_words
    b.emit_call(func_main_xxtea);
    b.emit_loadr(1);
    b.emit_halt();

    return entry;
}

/* ============================================================
 * CNTVCT_EL0 hardware counter for precise timing (ARM64 only)
 * ============================================================ */
static inline uint64_t read_cntvct(void) {
#if defined(__aarch64__)
    uint64_t val;
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static inline uint64_t read_cntfrq(void) {
#if defined(__aarch64__)
    uint64_t val;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
#else
    return 1000000000ULL;  /* clock_gettime returns nanoseconds */
#endif
}

/* ============================================================
 * C entry point — called from native-lib.cpp
 * ============================================================ */
int64_t vm_heavy_execute(JNIEnv *env, jobject callback_obj, int arg) {
    /* Resolve Java callback methods */
    HeavyVM vm;
    memset(&vm, 0, sizeof(vm));
    vm.env = env;
    vm.callback_obj = callback_obj;
    vm.max_steps = 50000000LL;  /* 50M steps max */

    if (env && callback_obj) {
        jclass cls = env->GetObjectClass(callback_obj);
        if (cls) {
            vm.mid_callback   = env->GetMethodID(cls, "vmCallback", "(III)I");
            vm.mid_get_string = env->GetMethodID(cls, "vmGetString", "(I)Ljava/lang/String;");
            vm.mid_log        = env->GetMethodID(cls, "vmLog", "(Ljava/lang/String;)V");
            vm.mid_base64     = env->GetMethodID(cls, "vmBase64Encode", "(J)Ljava/lang/String;");
            env->DeleteLocalRef(cls);
        }
    }

    /* Build bytecode */
    BytecodeBuilder builder;
    int entry_pc = build_stress_program(builder, arg);

    /* Run — start at entry point, not position 0 */
    vm.pc = entry_pc;

    uint64_t t0 = read_cntvct();
    int64_t result = vm_heavy_run(vm, builder.code.data(), (int)builder.code.size());
    uint64_t t1 = read_cntvct();

    uint64_t elapsed = t1 - t0;
    uint64_t freq = read_cntfrq();
    double ms = (double)elapsed / (double)freq * 1000.0;

    LOGI("vm_heavy: arg=%d steps=%lld result=%lld cntvct=%llu (%.2f ms, freq=%llu)",
         arg, (long long)vm.steps, (long long)result,
         (unsigned long long)elapsed, ms, (unsigned long long)freq);
    return result;
}

/* ============================================================
 * XXTEA VM entry point — runs modified XXTEA as bytecode
 * ============================================================ */
int64_t vm_xxtea_execute(JNIEnv *env, jobject callback_obj, int n_words) {
    HeavyVM vm;
    memset(&vm, 0, sizeof(vm));
    vm.env = env;
    vm.callback_obj = callback_obj;
    vm.max_steps = 50000000LL;

    if (env && callback_obj) {
        jclass cls = env->GetObjectClass(callback_obj);
        if (cls) {
            vm.mid_callback   = env->GetMethodID(cls, "vmCallback", "(III)I");
            vm.mid_get_string = env->GetMethodID(cls, "vmGetString", "(I)Ljava/lang/String;");
            vm.mid_log        = env->GetMethodID(cls, "vmLog", "(Ljava/lang/String;)V");
            vm.mid_base64     = env->GetMethodID(cls, "vmBase64Encode", "(J)Ljava/lang/String;");
            env->DeleteLocalRef(cls);
        }
    }

    BytecodeBuilder builder;
    int entry_pc = build_xxtea_program(builder, n_words);
    vm.pc = entry_pc;

    uint64_t t0 = read_cntvct();
    int64_t result = vm_heavy_run(vm, builder.code.data(), (int)builder.code.size());
    uint64_t t1 = read_cntvct();

    uint64_t elapsed = t1 - t0;
    uint64_t freq = read_cntfrq();
    double ms = (double)elapsed / (double)freq * 1000.0;

    LOGI("vm_xxtea: n_words=%d steps=%lld result=%lld cntvct=%llu (%.2f ms)",
         n_words, (long long)vm.steps, (long long)result,
         (unsigned long long)elapsed, ms);
    return result;
}
