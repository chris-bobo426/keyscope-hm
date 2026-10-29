/*
 * dynamic/disasm_experiment/zeroize_compare.c
 * 鸿钥卫士 KeyScope-HM v3.0 —— E1 (M4 / CWE-14) 编译器死存储消除 (DSE) 实证靶标程序
 *
 * 对比三种密钥缓冲区清理实现在 -O0 与 -O2 编译优化下的机器码保留情况：
 * 1. wipe_with_plain_memset: 使用普通 memset(key, 0, 16) -> 在 -O2 下被编译器死存储消除 (DSE) 完全删去！
 * 2. wipe_with_volatile_cleanse: 使用 volatile 指针逐字节覆写 (OPENSSL_cleanse 模式) -> 在 -O2 下完整保留！
 * 3. wipe_with_CompilerBarrier: 使用 memory barrier (explicit_bzero 模式) -> 在 -O2 下完整保留！
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern void use_key_for_sm4_encrypt(const uint8_t* key, size_t len, uint8_t* out_tag);

/* 风险实现：普通 memset 在函数返回前清零局部栈上的密钥缓冲区 */
int wipe_with_plain_memset(const uint8_t* seed, uint8_t* out_tag) {
    uint8_t session_key[16];
    for (int i = 0; i < 16; i++) {
        session_key[i] = seed[i] ^ (uint8_t)(0x5A + i);
    }
    use_key_for_sm4_encrypt(session_key, 16, out_tag);

    /* CWE-14: 编译器发现在此之后 session_key 生命周期结束且不再被读取，-O2 优化直接删除此调用 */
    memset(session_key, 0, sizeof(session_key));
    return 0;
}

/* 安全实现 1：volatile 覆写循环 (对应 OPENSSL_cleanse / 安全擦除原语) */
int wipe_with_volatile_cleanse(const uint8_t* seed, uint8_t* out_tag) {
    uint8_t session_key[16];
    for (int i = 0; i < 16; i++) {
        session_key[i] = seed[i] ^ (uint8_t)(0x5A + i);
    }
    use_key_for_sm4_encrypt(session_key, 16, out_tag);

    volatile uint8_t* p = (volatile uint8_t*)session_key;
    for (size_t i = 0; i < sizeof(session_key); i++) {
        p[i] = 0;
    }
    return 0;
}

/* 安全实现 2：带编译器内存屏障的 explicit_bzero 风格擦除 */
int wipe_with_explicit_barrier(const uint8_t* seed, uint8_t* out_tag) {
    uint8_t session_key[16];
    for (int i = 0; i < 16; i++) {
        session_key[i] = seed[i] ^ (uint8_t)(0x5A + i);
    }
    use_key_for_sm4_encrypt(session_key, 16, out_tag);

    memset(session_key, 0, sizeof(session_key));
    __asm__ __volatile__("" : : "r"(session_key) : "memory");
    return 0;
}
