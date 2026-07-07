/*
 * xxtea.cpp — Modified XXTEA encryption + base64 encoding for wxtrace demo.
 *
 * This file implements a "magic-modified" XXTEA block cipher with the custom
 * MX macro, encrypts a random string, hex-encodes the ciphertext, then
 * base64-encodes the hex via JNI (java.util.Base64). A pure-native base64
 * encoder is also included for comparison.
 *
 * Designed as a trace target: the XXTEA inner loop has rich control flow
 * (modulo, XOR, shift, conditional branches) making it ideal for BB tracing.
 */

#include <jni.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "wxtrace-demo"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* ============================================================
 * Modified XXTEA — custom MX macro
 * ============================================================ */

#define MX  (((z >> 7) ^ (y << 3)) + ((y >> 5) ^ (z << 6)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))

#define DELTA 0x9e3779b9
#define XXTEA_ROUNDS(n) ((6 + 52 / (n)) * (n))

/**
 * Modified XXTEA encrypt.
 *
 * @param v     Array of uint32_t words (plaintext). Modified in-place.
 * @param n     Number of words in v.
 * @param key   128-bit key as 4 uint32_t words.
 */
extern "C" __attribute__((noinline))
void xxtea_encrypt(uint32_t *v, int n, const uint32_t *key) {
    if (n < 2) return;

    uint32_t y, z, sum = 0;
    uint32_t p, rounds, e;

    rounds = XXTEA_ROUNDS(n);
    z = v[n - 1];

    for (p = 0; p < rounds; p++) {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (int q = 0; q < n - 1; q++) {
            y = v[q + 1];
            v[q] += MX;
            z = v[q];
        }
        y = v[0];
        v[n - 1] += MX;
        z = v[n - 1];
    }
}

/**
 * Modified XXTEA decrypt.
 */
__attribute__((noinline))
static void xxtea_decrypt(uint32_t *v, int n, const uint32_t *key) {
    if (n < 2) return;

    uint32_t y, z, sum;
    uint32_t p, rounds, e;

    rounds = XXTEA_ROUNDS(n);
    sum = rounds * DELTA;
    y = v[0];

    for (p = 0; p < rounds; p++) {
        e = (sum >> 2) & 3;
        for (int q = n - 1; q > 0; q--) {
            z = v[q - 1];
            v[q] -= MX;
            y = v[q];
        }
        z = v[n - 1];
        v[0] -= MX;
        y = v[0];
        sum -= DELTA;
    }
}

/* ============================================================
 * Random string generation
 * ============================================================ */

__attribute__((noinline))
static void generate_random_string(char *buf, size_t len) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned)time(nullptr) ^ (unsigned)getpid());
        seeded = true;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buf[len] = '\0';
}

/* ============================================================
 * Hex encoding
 * ============================================================ */

__attribute__((noinline))
static void bytes_to_hex(const uint8_t *data, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    out[len * 2] = '\0';
}

/* ============================================================
 * Native base64 encoder (for comparison with JNI version)
 * ============================================================ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__attribute__((noinline))
static char *base64_encode_native(const uint8_t *data, size_t len, char *out, size_t out_size) {
    size_t olen = 4 * ((len + 2) / 3);
    if (out_size < olen + 1) return nullptr;

    size_t i = 0, j = 0;
    while (i + 2 < len) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        out[j++] = b64_table[(n >> 18) & 0x3f];
        out[j++] = b64_table[(n >> 12) & 0x3f];
        out[j++] = b64_table[(n >> 6) & 0x3f];
        out[j++] = b64_table[n & 0x3f];
        i += 3;
    }
    if (i < len) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
        out[j++] = b64_table[(n >> 18) & 0x3f];
        out[j++] = b64_table[(n >> 12) & 0x3f];
        out[j++] = (i + 1 < len) ? b64_table[(n >> 6) & 0x3f] : '=';
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

/* ============================================================
 * Full pipeline: random string → XXTEA encrypt → hex → base64
 * ============================================================ */

/**
 * xxtea_encrypt_and_base64 — the main entry point.
 *
 * 1. Generate a random string of `str_len` characters
 * 2. Pad to uint32_t boundary, encrypt with modified XXTEA
 * 3. Hex-encode the ciphertext
 * 4. Base64-encode the hex string using JNI (java.util.Base64)
 * 5. Return the base64 result as a char*
 *
 * @param env         JNI environment (for base64 encoding)
 * @param str_len     Length of random string to generate
 * @param out_base64  Output buffer for base64 result
 * @param out_size    Size of output buffer
 * @return            Pointer to out_base64, or nullptr on error
 */
extern "C" __attribute__((noinline))
char *xxtea_encrypt_and_base64(JNIEnv *env, int str_len,
                                       char *out_base64, size_t out_size) {
    if (str_len <= 0 || str_len > 4096) return nullptr;

    /* 1. Generate random string */
    char *plaintext = (char *)malloc(str_len + 1);
    if (!plaintext) return nullptr;
    generate_random_string(plaintext, str_len);

    /* 2. Convert to uint32_t words (little-endian, pad with zeros) */
    int n_words = (str_len + 3) / 4;
    uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
    if (!words) { free(plaintext); return nullptr; }
    memcpy(words, plaintext, str_len);

    /* 3. Encrypt with modified XXTEA */
    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};
    xxtea_encrypt(words, n_words, key);

    /* 4. Hex-encode the ciphertext */
    size_t hex_len = n_words * 4 * 2;
    char *hex_str = (char *)malloc(hex_len + 1);
    if (!hex_str) { free(plaintext); free(words); return nullptr; }
    bytes_to_hex((const uint8_t *)words, n_words * 4, hex_str);

    /* 5. Base64-encode via JNI */
    if (env) {
        /* Call java.util.Base64.getEncoder().encodeToString(hex_str.getBytes()) */
        jclass base64_cls = env->FindClass("java/util/Base64");
        if (base64_cls) {
            jmethodID get_encoder = env->GetStaticMethodID(
                base64_cls, "getEncoder", "()Ljava/util/Base64$Encoder;");
            if (get_encoder) {
                jobject encoder = env->CallStaticObjectMethod(base64_cls, get_encoder);
                if (encoder) {
                    jclass encoder_cls = env->GetObjectClass(encoder);
                    jmethodID encode_to_string = env->GetMethodID(
                        encoder_cls, "encodeToString", "([B)Ljava/lang/String;");

                    /* Convert hex string to byte array */
                    jbyteArray jhex = env->NewByteArray((jsize)hex_len);
                    env->SetByteArrayRegion(jhex, 0, (jsize)hex_len, (const jbyte *)hex_str);

                    /* Encode */
                    jstring jbase64 = (jstring)env->CallObjectMethod(encoder, encode_to_string, jhex);
                    if (jbase64) {
                        const char *b64 = env->GetStringUTFChars(jbase64, nullptr);
                        size_t b64_len = strlen(b64);
                        if (b64_len < out_size) {
                            memcpy(out_base64, b64, b64_len + 1);
                        }
                        env->ReleaseStringUTFChars(jbase64, b64);
                        env->DeleteLocalRef(jbase64);
                    }
                    env->DeleteLocalRef(jhex);
                    env->DeleteLocalRef(encoder);
                    env->DeleteLocalRef(encoder_cls);
                }
            }
            env->DeleteLocalRef(base64_cls);
        }
    }

    free(plaintext);
    free(words);
    free(hex_str);
    return out_base64;
}

/**
 * xxtea_encrypt_and_base64_native — same pipeline but with native base64.
 * Used for comparison / verification.
 */
__attribute__((noinline))
static char *xxtea_encrypt_and_base64_native(int str_len,
                                              char *out_base64, size_t out_size) {
    if (str_len <= 0 || str_len > 4096) return nullptr;

    char *plaintext = (char *)malloc(str_len + 1);
    if (!plaintext) return nullptr;
    generate_random_string(plaintext, str_len);

    int n_words = (str_len + 3) / 4;
    uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
    if (!words) { free(plaintext); return nullptr; }
    memcpy(words, plaintext, str_len);

    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};
    xxtea_encrypt(words, n_words, key);

    /* Base64-encode the raw ciphertext (not hex) for native version */
    base64_encode_native((const uint8_t *)words, n_words * 4, out_base64, out_size);

    free(plaintext);
    free(words);
    return out_base64;
}

/**
 * xxtea_verify — encrypt then decrypt, check roundtrip.
 * Returns 1 if roundtrip succeeds, 0 otherwise.
 */
extern "C" __attribute__((noinline))
int xxtea_verify(const char *input, size_t len) {
    int n_words = (int)((len + 3) / 4);
    uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
    uint32_t *backup = (uint32_t *)calloc(n_words, sizeof(uint32_t));
    if (!words || !backup) { free(words); free(backup); return 0; }

    memcpy(words, input, len);
    memcpy(backup, input, len);

    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};
    xxtea_encrypt(words, n_words, key);
    xxtea_decrypt(words, n_words, key);

    int ok = (memcmp(words, backup, n_words * 4) == 0);
    free(words);
    free(backup);
    return ok;
}

/* ============================================================
 * JNI exports
 * ============================================================ */

/**
 * Native method: encrypt random string with XXTEA, base64 via JNI.
 * Returns the base64 string.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_wx_trace_demo_MainActivity_xxteaEncrypt(JNIEnv *env, jobject, jint str_len) {
    char buf[8192];
    char *result = xxtea_encrypt_and_base64(env, str_len, buf, sizeof(buf));
    if (result) {
        LOGI("xxtea_encrypt: len=%d base64=%.64s...", str_len, buf);
        return env->NewStringUTF(buf);
    }
    return env->NewStringUTF("ERROR");
}

/**
 * Native method: encrypt random string with XXTEA, native base64.
 * For comparison with the JNI version.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_wx_trace_demo_MainActivity_xxteaEncryptNative(JNIEnv *env, jobject, jint str_len) {
    char buf[8192];
    char *result = xxtea_encrypt_and_base64_native(str_len, buf, sizeof(buf));
    if (result) {
        return env->NewStringUTF(buf);
    }
    return env->NewStringUTF("ERROR");
}

/**
 * Native method: verify XXTEA roundtrip.
 */
/**
 * Verify with fixed deterministic data (same as VM heap fill).
 * Returns checksum of ciphertext. 
 * data[i] = (i * 2654435761) >> 16  (same as VM heap fill)
 */
extern "C" __attribute__((noinline))
long xxtea_encrypt_deterministic(int n_words) {
    if (n_words <= 0 || n_words > 1024) return 0;

    uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
    if (!words) return 0;

    /* Same data generation as VM: v[i] = (i * 2654435761) >> 16 */
    for (int i = 0; i < n_words; i++) {
        words[i] = (uint32_t)(((uint64_t)i * 2654435761ULL) >> 16);
    }

    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};
    xxtea_encrypt(words, n_words, key);

    /* Compute checksum: XOR of all words * (i+1) */
    long checksum = 0;
    for (int i = 0; i < n_words; i++) {
        checksum ^= (long)(words[i] * (i + 1));
    }

    free(words);
    return checksum;
}

/**
 * JNI: compare native C XXTEA vs VM bytecode XXTEA with same deterministic data.
 * Both use the same key and same plaintext generation.
 * Note: results differ because native uses uint32_t arithmetic, VM uses int64_t.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_wx_trace_demo_MainActivity_xxteaCompareWithVm(JNIEnv *env, jobject, jint n_words) {
    /* Native version */
    long native_cs = xxtea_encrypt_deterministic(n_words);

    char buf[512];
    snprintf(buf, sizeof(buf),
        "n_words=%d  native_cs=%ld  "
        "(VM uses int64_t arithmetic, native uses uint32_t — values will differ; "
        "both are deterministic. Run xxteaVm to get VM checksum.)",
        n_words, native_cs);
    LOGI("xxtea_compare: %s", buf);
    return env->NewStringUTF(buf);
}

/**
 * Native method: verify XXTEA roundtrip.
 */
extern "C" JNIEXPORT jint JNICALL
Java_wx_trace_demo_MainActivity_xxteaVerify(JNIEnv *, jobject, jstring input) {
    const char *test = "Hello, wxtrace XXTEA test!";
    return xxtea_verify(test, strlen(test));
}

/**
 * Run XXTEA workload N times (for trace pressure testing).
 * Each iteration: generate random string → encrypt → hex → base64 via JNI.
 */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runXxteaWorkload(JNIEnv *env, jobject, jint iterations) {
    char buf[8192];
    long checksum = 0;

    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};

    for (int i = 0; i < iterations; i++) {
        /* Vary string length per iteration for more diverse traces */
        int str_len = 16 + (i * 7) % 128;

        /* Generate random string */
        char *plaintext = (char *)malloc(str_len + 1);
        if (!plaintext) continue;
        generate_random_string(plaintext, str_len);

        /* Convert to words */
        int n_words = (str_len + 3) / 4;
        uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
        if (!words) { free(plaintext); continue; }
        memcpy(words, plaintext, str_len);

        /* Encrypt with modified XXTEA */
        xxtea_encrypt(words, n_words, key);

        /* Hex-encode */
        size_t hex_len = n_words * 4 * 2;
        char *hex_str = (char *)malloc(hex_len + 1);
        if (hex_str) {
            bytes_to_hex((const uint8_t *)words, n_words * 4, hex_str);

            /* Base64-encode via JNI */
            if (env) {
                jclass base64_cls = env->FindClass("java/util/Base64");
                if (base64_cls) {
                    jmethodID get_encoder = env->GetStaticMethodID(
                        base64_cls, "getEncoder", "()Ljava/util/Base64$Encoder;");
                    if (get_encoder) {
                        jobject encoder = env->CallStaticObjectMethod(base64_cls, get_encoder);
                        if (encoder) {
                            jclass encoder_cls = env->GetObjectClass(encoder);
                            jmethodID encode_to_string = env->GetMethodID(
                                encoder_cls, "encodeToString", "([B)Ljava/lang/String;");
                            jbyteArray jhex = env->NewByteArray((jsize)hex_len);
                            env->SetByteArrayRegion(jhex, 0, (jsize)hex_len, (const jbyte *)hex_str);
                            jstring jbase64 = (jstring)env->CallObjectMethod(encoder, encode_to_string, jhex);
                            if (jbase64) {
                                const char *b64 = env->GetStringUTFChars(jbase64, nullptr);
                                checksum += (long)strlen(b64);
                                env->ReleaseStringUTFChars(jbase64, b64);
                                env->DeleteLocalRef(jbase64);
                            }
                            env->DeleteLocalRef(jhex);
                            env->DeleteLocalRef(encoder);
                            env->DeleteLocalRef(encoder_cls);
                        }
                    }
                    env->DeleteLocalRef(base64_cls);
                }
            }
            free(hex_str);
        }

        /* Add first word of ciphertext to checksum */
        checksum += (long)words[0];

        free(plaintext);
        free(words);
    }

    LOGI("xxtea_workload: %d iterations, checksum=%ld", iterations, checksum);
    return (jlong)checksum;
}

/**
 * Pure native XXTEA workload (no JNI calls).
 * For tracing the XXTEA algorithm itself without JNI noise.
 */
extern "C" JNIEXPORT jlong JNICALL
Java_wx_trace_demo_MainActivity_runXxteaPureNative(JNIEnv *, jobject, jint iterations) {
    long checksum = 0;
    const uint32_t key[4] = {0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0};

    for (int i = 0; i < iterations; i++) {
        int str_len = 16 + (i * 7) % 128;
        char *plaintext = (char *)malloc(str_len + 1);
        if (!plaintext) continue;
        generate_random_string(plaintext, str_len);

        int n_words = (str_len + 3) / 4;
        uint32_t *words = (uint32_t *)calloc(n_words, sizeof(uint32_t));
        if (!words) { free(plaintext); continue; }
        memcpy(words, plaintext, str_len);

        /* Encrypt */
        xxtea_encrypt(words, n_words, key);

        /* Native base64 */
        char b64_buf[8192];
        base64_encode_native((const uint8_t *)words, n_words * 4, b64_buf, sizeof(b64_buf));
        checksum += (long)strlen(b64_buf) + (long)words[0];

        /* Verify roundtrip */
        xxtea_decrypt(words, n_words, key);
        checksum += (long)words[0];

        free(plaintext);
        free(words);
    }

    LOGI("xxtea_pure_native: %d iterations, checksum=%ld", iterations, checksum);
    return (jlong)checksum;
}
