#include <napi/native_api.h>
#include <openssl/rand.h>
#include <string.h>

static napi_value AcquireCopiedKeyBuffer(napi_env env, napi_callback_info info) {
    uint8_t localKeyBuf[16];
    RAND_bytes(localKeyBuf, 16);
    void* copyPtr = nullptr;
    napi_value copiedBuf = nullptr;
    // 拷贝语义：创建了独立副本，且 Native 原件仅用了会被 -O2 消除的普通 memset (或未清零)
    napi_create_buffer_copy(env, 16, localKeyBuf, &copyPtr, &copiedBuf);
    memset(localKeyBuf, 0, 16);
    return copiedBuf;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "acquireKeyBuffer", nullptr, AcquireCopiedKeyBuffer, nullptr, nullptr, nullptr, napi_default, nullptr }
    };
    napi_define_properties(env, exports, 1, desc);
    return exports;
}
