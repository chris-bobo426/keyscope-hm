#include <napi/native_api.h>
#include <openssl/rand.h>

static uint8_t g_sharedKeyBuf[16];

static napi_value AcquireSharedKeyBuffer(napi_env env, napi_callback_info info) {
    RAND_bytes(g_sharedKeyBuf, 16);
    napi_value extBuf = nullptr;
    // 别名共享：ArkTS ArrayBuffer 直接指向 g_sharedKeyBuf 同一块内存
    napi_create_external_arraybuffer(env, g_sharedKeyBuf, 16, nullptr, nullptr, &extBuf);
    return extBuf;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "acquireKeyBuffer", nullptr, AcquireSharedKeyBuffer, nullptr, nullptr, nullptr, napi_default, nullptr }
    };
    napi_define_properties(env, exports, 1, desc);
    return exports;
}
