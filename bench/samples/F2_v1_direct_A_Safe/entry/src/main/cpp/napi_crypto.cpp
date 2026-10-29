#include <napi/native_api.h>
#include <openssl/rand.h>
#include <string.h>

static napi_value DeriveSessionKeySafe(napi_env env, napi_callback_info info) {
    uint8_t sessionBuf[16];
    RAND_bytes(sessionBuf, 16);
    void* copyPtr = nullptr;
    napi_value arrayBuf = nullptr;
    napi_create_buffer_copy(env, 16, sessionBuf, &copyPtr, &arrayBuf);
    memset_s(sessionBuf, 16, 0, 16);
    return arrayBuf;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "deriveSessionKeyBridge", nullptr, DeriveSessionKeySafe, nullptr, nullptr, nullptr, napi_default, nullptr }
    };
    napi_define_properties(env, exports, 1, desc);
    return exports;
}
