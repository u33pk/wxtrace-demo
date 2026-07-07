#include <jni.h>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "wxtrace-demo"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/*
 * wxtrace demo — a "trace testbed" of native functions exercising a variety
 * of control-flow shapes, so the W^X shadow trace tool has rich material to
 * trace (single BP, basic-block, fork, read-hiding).
 *
 * Every target function is marked noinline so it keeps a stable symbol and
 * its own code range. Startup logs each function's offset within libdemo.so
 * (via dladdr) so test scripts can resolve addresses dynamically instead of
 * hardcoding an offset.
 */

/* ============================================================
 * 1. Simple counting loop (single-BP / baseline)
 * ============================================================ */
__attribute__((noinline))
static int compute_value(int n) {
    int result = 0;
    for (int i = 0; i < n; i++) {
        result += (i * 7) ^ (i << 3);
    }
    return result;
}

/* ============================================================
 * 2. CRC32 — tight bit-twiddling loop
 * ============================================================ */
__attribute__((noinline))
static uint32_t compute_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}

/* CRC32 over an arbitrary memory region — used to checksum a function's own
 * code bytes (read-hiding test: traced vs original should differ only when
 * read-hiding is OFF). */
__attribute__((noinline))
static uint32_t region_crc32(const void *addr, size_t len) {
    return compute_crc32((const uint8_t *)addr, len);
}

/* ============================================================
 * 3. Recursion — call graph / depth
 * ============================================================ */
__attribute__((noinline))
static long fibonacci(int n) {
    if (n < 2)
        return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

/* ============================================================
 * 4. Insertion sort — nested loops + data-dependent branches
 * ============================================================ */
__attribute__((noinline))
static void insertion_sort(int *a, int n) {
    for (int i = 1; i < n; i++) {
        int key = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > key) {
            a[j + 1] = a[j];
            j--;
        }
        a[j + 1] = key;
    }
}

__attribute__((noinline))
static long array_sum(const int *a, int n) {
    long s = 0;
    for (int i = 0; i < n; i++)
        s += a[i];
    return s;
}

/* ============================================================
 * 5. Matrix multiply — triple nested loop (BB-heavy)
 * ============================================================ */
#define MAT_N 8
__attribute__((noinline))
static long mat_mul_trace(const int *A, const int *B, int *C, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            int acc = 0;
            for (int k = 0; k < n; k++)
                acc += A[i * n + k] * B[k * n + j];
            C[i * n + j] = acc;
        }
    }
    long checksum = 0;
    for (int i = 0; i < n * n; i++)
        checksum += C[i];
    return checksum;
}

/* ============================================================
 * 6. Stack bytecode VM — the "complex algorithm".
 *
 * A small stack machine with a switch-dispatch fetch/decode/execute loop.
 * The dispatch switch fans out into many basic blocks, making this an ideal
 * BB-trace target (each opcode handler is its own block, reached via an
 * indirect/range branch). Deterministic and verifiable.
 *
 * Opcodes (1 byte; some take a 1-byte operand that follows):
 *   0  HALT
 *   1  PUSH imm     push imm
 *   2  ADD          b=pop,a=pop, push a+b
 *   3  SUB          push a-b
 *   4  MUL          push a*b
 *   5  DUP          push top
 *   6  SWAP         swap top two
 *   7  JMP  target  pc = target (byte index)
 *   8  JZ   target  v=pop; if v==0 pc=target
 *   9  LOAD slot    push reg[slot]
 *   10 STORE slot   reg[slot] = pop
 *   11 XOR          push a^b
 *   12 MOD          push a%b  (b!=0)
 * Result = value left on top of stack at HALT.
 * ============================================================ */
enum {
    OP_HALT = 0, OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_DUP, OP_SWAP,
    OP_JMP, OP_JZ, OP_LOAD, OP_STORE, OP_XOR, OP_MOD,
};

__attribute__((noinline))
static long vm_execute(const uint8_t *prog, int len, int input) {
    long stack[64];
    long reg[8] = {0};
    int sp = 0;
    int pc = 0;
    long steps = 0;
    const long MAX_STEPS = 1000000;

    reg[0] = input;  /* program input available in reg0 */

    while (pc >= 0 && pc < len && steps++ < MAX_STEPS) {
        uint8_t op = prog[pc++];
        switch (op) {
        case OP_HALT:
            goto done;
        case OP_PUSH:
            stack[sp++] = (int8_t)prog[pc++];
            break;
        case OP_ADD: {
            long b = stack[--sp], a = stack[--sp];
            stack[sp++] = a + b;
            break;
        }
        case OP_SUB: {
            long b = stack[--sp], a = stack[--sp];
            stack[sp++] = a - b;
            break;
        }
        case OP_MUL: {
            long b = stack[--sp], a = stack[--sp];
            stack[sp++] = a * b;
            break;
        }
        case OP_DUP:
            stack[sp] = stack[sp - 1];
            sp++;
            break;
        case OP_SWAP: {
            long t = stack[sp - 1];
            stack[sp - 1] = stack[sp - 2];
            stack[sp - 2] = t;
            break;
        }
        case OP_JMP:
            pc = prog[pc];
            break;
        case OP_JZ: {
            uint8_t target = prog[pc++];
            if (stack[--sp] == 0)
                pc = target;
            break;
        }
        case OP_LOAD:
            stack[sp++] = reg[prog[pc++] & 7];
            break;
        case OP_STORE:
            reg[prog[pc++] & 7] = stack[--sp];
            break;
        case OP_XOR: {
            long b = stack[--sp], a = stack[--sp];
            stack[sp++] = a ^ b;
            break;
        }
        case OP_MOD: {
            long b = stack[--sp], a = stack[--sp];
            stack[sp++] = b ? a % b : 0;
            break;
        }
        default:
            goto done;
        }
        if (sp < 0 || sp >= 63)
            break;
    }
done:
    return sp > 0 ? stack[sp - 1] : 0;
}

/*
 * Sample VM program: result = sum_{k=1..input} k = input*(input+1)/2
 *
 *  idx op           bytes
 *  0:  PUSH 0       1,0
 *  2:  STORE 1      10,1        ; acc = 0
 *  4:  LOAD 0       9,0   (loop); push n
 *  6:  JZ 24        8,24        ; if n==0 -> end
 *  8:  LOAD 1       9,1
 *  10: LOAD 0       9,0
 *  12: ADD          2           ; acc += n
 *  13: STORE 1      10,1
 *  15: LOAD 0       9,0
 *  17: PUSH 1       1,1
 *  19: SUB          3           ; n -= 1
 *  20: STORE 0      10,0
 *  22: JMP 4        7,4
 *  24: LOAD 1       9,1   (end)
 *  26: HALT         0
 */
static const uint8_t kSumProgram[] = {
    OP_PUSH, 0, OP_STORE, 1,
    OP_LOAD, 0, OP_JZ, 24,
    OP_LOAD, 1, OP_LOAD, 0, OP_ADD, OP_STORE, 1,
    OP_LOAD, 0, OP_PUSH, 1, OP_SUB, OP_STORE, 0,
    OP_JMP, 4,
    OP_LOAD, 1, OP_HALT,
};

/* ============================================================
 * Function info (offsets within libdemo.so) for test scripts
 * ============================================================ */
/* vm_heavy entry point — defined in vm_heavy.cpp */
extern int64_t vm_heavy_execute(JNIEnv *env, jobject callback_obj, int arg);
/* vm_heavy hot loop — the actual 3M-step interpreter */
struct HeavyVM;  /* forward decl */
extern int64_t vm_heavy_run(HeavyVM &vm, const uint8_t *prog, int prog_len);

/* xxtea workload — defined in xxtea.cpp */
extern "C" void xxtea_encrypt(uint32_t *v, int n, const uint32_t *key);
extern "C" char *xxtea_encrypt_and_base64(JNIEnv *env, int str_len, char *out, size_t out_size);
extern "C" int xxtea_verify(const char *input, size_t len);
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runXxteaWorkload(JNIEnv *env, jobject, jint iterations);
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runXxteaPureNative(JNIEnv *, jobject, jint iterations);

/* vm xxtea — defined in vm_heavy.cpp */
extern int64_t vm_xxtea_execute(JNIEnv *env, jobject callback_obj, int n_words);

struct func_entry { const char *name; const void *addr; };

static const func_entry *demo_funcs(int *count) {
    static const func_entry funcs[] = {
        {"compute_value",    (const void *)&compute_value},
        {"compute_crc32",    (const void *)&compute_crc32},
        {"region_crc32",     (const void *)&region_crc32},
        {"fibonacci",        (const void *)&fibonacci},
        {"insertion_sort",   (const void *)&insertion_sort},
        {"array_sum",        (const void *)&array_sum},
        {"mat_mul_trace",    (const void *)&mat_mul_trace},
        {"vm_execute",       (const void *)&vm_execute},
        {"vm_heavy_execute", (const void *)&vm_heavy_execute},
        {"vm_heavy_run",     (const void *)&vm_heavy_run},
        {"xxtea_encrypt",    (const void *)&xxtea_encrypt},
        {"xxtea_base64",     (const void *)&xxtea_encrypt_and_base64},
        {"xxtea_verify",     (const void *)&xxtea_verify},
        {"vm_xxtea_execute", (const void *)&vm_xxtea_execute},
    };
    *count = (int)(sizeof(funcs) / sizeof(funcs[0]));
    return funcs;
}

static std::string build_func_info() {
    int n = 0;
    const func_entry *f = demo_funcs(&n);
    Dl_info info;
    const void *base = nullptr;
    if (dladdr((const void *)&vm_execute, &info))
        base = info.dli_fbase;

    char line[160];
    std::string out;
    snprintf(line, sizeof(line), "libdemo base=%p\n", base);
    out += line;
    for (int i = 0; i < n; i++) {
        unsigned long off = base ? (unsigned long)((const char *)f[i].addr - (const char *)base) : 0;
        snprintf(line, sizeof(line), "%-16s off=0x%lx abs=%p\n",
                 f[i].name, off, f[i].addr);
        out += line;
        LOGI("func %-16s off=0x%lx abs=%p", f[i].name, off, f[i].addr);
    }
    return out;
}

/* ============================================================
 * Dispatch: run a named workload (shared by buttons + intent)
 * ============================================================ */
static long run_workload(const char *name, int arg) {
    if (strcmp(name, "computeValue") == 0)
        return compute_value(arg ? arg : 100000);
    if (strcmp(name, "crc32") == 0) {
        const char *s = "hello world";
        return compute_crc32((const uint8_t *)s, strlen(s));
    }
    if (strcmp(name, "vm") == 0)
        return vm_execute(kSumProgram, sizeof(kSumProgram), arg ? arg : 100);
    if (strcmp(name, "fib") == 0)
        return fibonacci(arg ? arg : 24);
    if (strcmp(name, "sort") == 0) {
        int a[128];
        int n = (arg > 0 && arg <= 128) ? arg : 64;
        uint32_t s = 0x12345678u;
        for (int i = 0; i < n; i++) { s = s * 1103515245u + 12345u; a[i] = (int)(s >> 16) & 0x3ff; }
        insertion_sort(a, n);
        return array_sum(a, n);
    }
    if (strcmp(name, "matrix") == 0) {
        int A[MAT_N * MAT_N], B[MAT_N * MAT_N], C[MAT_N * MAT_N];
        for (int i = 0; i < MAT_N * MAT_N; i++) { A[i] = (i * 3 + 1) & 7; B[i] = (i * 5 + 2) & 7; }
        return mat_mul_trace(A, B, C, MAT_N);
    }
    if (strcmp(name, "heavy") == 0)
        return (long)vm_heavy_execute(nullptr, nullptr, arg ? arg : 500);
    if (strcmp(name, "all") == 0) {
        long r = 0;
        r += run_workload("computeValue", 10000);
        r += run_workload("crc32", 0);
        r += run_workload("vm", 100);
        r += run_workload("fib", 20);
        r += run_workload("sort", 64);
        r += run_workload("matrix", 0);
        return r;
    }
    return -1;
}

/* ============================================================
 * JNI exports
 * ============================================================ */
extern "C" JNIEXPORT jstring JNICALL
Java_wx_trace_demo_MainActivity_stringFromJNI(JNIEnv *env, jobject) {
    return env->NewStringUTF("wxtrace demo — native testbed loaded");
}

extern "C" JNIEXPORT jint JNICALL
Java_wx_trace_demo_MainActivity_computeValue(JNIEnv *, jobject, jint n) {
    return compute_value(n);
}

extern "C" JNIEXPORT jint JNICALL
Java_wx_trace_demo_MainActivity_computeCrc32(JNIEnv *env, jobject, jstring input) {
    const char *str = env->GetStringUTFChars(input, nullptr);
    size_t len = env->GetStringUTFLength(input);
    uint32_t result = compute_crc32((const uint8_t *)str, len);
    env->ReleaseStringUTFChars(input, str);
    return (jint)result;
}

/*
 * JNI burst — make real JNI calls so the curated entry hooks fire with a
 * return_addr inside libdemo. Needs a JNIEnv (uses the one passed to the
 * runWorkload JNI wrapper, valid on the calling thread).
 */
__attribute__((noinline))
static long jni_burst(JNIEnv *env, int n) {
    long acc = 0;
    if (n <= 0) n = 4;
    for (int i = 0; i < n; i++) {
        jclass cls = env->FindClass("java/lang/String");
        jstring s = env->NewStringUTF("wxtrace");
        if (s) {
            jsize len = env->GetStringUTFLength(s);
            const char *p = env->GetStringUTFChars(s, nullptr);
            if (p) { acc += (unsigned char)p[0] + len; env->ReleaseStringUTFChars(s, p); }
            env->DeleteLocalRef(s);
        }
        if (cls) { acc++; env->DeleteLocalRef(cls); }
    }
    return acc;
}

/* Run a named workload; returns the result as a long. */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runWorkload(JNIEnv *env, jobject, jstring name, jint arg) {
    const char *n = env->GetStringUTFChars(name, nullptr);
    long r;
    if (strcmp(n, "jni") == 0)
        r = jni_burst(env, arg);          /* needs env → handled here */
    else
        r = run_workload(n, arg);
    env->ReleaseStringUTFChars(name, n);
    return (jlong)r;
}

/* Heavy VM with JNI callback — passes the Java object to vm_heavy_execute
 * so the VM can call back into Java during execution. */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runHeavyWithCallback(JNIEnv *env, jobject thiz, jint arg) {
    return (jlong)vm_heavy_execute(env, thiz, arg);
}

/* XXTEA VM — runs modified XXTEA as HeavyVM bytecode with JNI base64 callback. */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runXxteaVm(JNIEnv *env, jobject thiz, jint n_words) {
    return (jlong)vm_xxtea_execute(env, thiz, n_words);
}

/*
 * Expose this process's JNIEnv* (and the JNINativeInterface table ptr) to
 * logcat. The app is not root and cannot call the wxtrace prctl itself; the
 * root controller reads this address from logcat and calls
 * prctl(JNI_SET_ENV, pid, env) on the target's behalf. The table pointer is
 * process-wide, so the main-thread env suffices to resolve it.
 */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_jniEnvAddr(JNIEnv *env, jobject) {
    void *table = *(void **)env;
    LOGI("JNIEnv=%p table=%p pid=%d", env, table, getpid());
    return (jlong)(uintptr_t)env;
}

/* Function offset table for test scripts. */
extern "C" JNIEXPORT jstring JNICALL
Java_wx_trace_demo_MainActivity_funcInfo(JNIEnv *env, jobject) {
    return env->NewStringUTF(build_func_info().c_str());
}

/* CRC32 over a code region — checksum a function to detect BRK tampering.
 * Under read-hiding the checksum stays equal to the untraced value. */
extern "C" JNIEXPORT jint JNICALL
Java_wx_trace_demo_MainActivity_crc32Region(JNIEnv *, jobject, jlong addr, jint len) {
    return (jint)region_crc32((const void *)(uintptr_t)addr, (size_t)len);
}

/* Absolute runtime address of a named target function (0 if unknown). */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_funcAddr(JNIEnv *env, jobject, jstring name) {
    const char *n = env->GetStringUTFChars(name, nullptr);
    int cnt = 0;
    const func_entry *f = demo_funcs(&cnt);
    jlong addr = 0;
    for (int i = 0; i < cnt; i++) {
        if (strcmp(n, f[i].name) == 0) { addr = (jlong)(uintptr_t)f[i].addr; break; }
    }
    env->ReleaseStringUTFChars(name, n);
    return addr;
}
