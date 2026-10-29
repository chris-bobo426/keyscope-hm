#include <napi/native_api.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

static napi_value DeriveSessionKeyRisky(napi_env env, napi_callback_info info) {
    uint8_t sessionBuf[16];
    RAND_bytes(sessionBuf, 16);
    char hexBuf[33];
    ToHex(hexBuf, sessionBuf);
    napi_value hexStr = nullptr;
    napi_create_string_utf8(env, hexBuf, NAPI_AUTO_LENGTH, &hexStr);
    memset_s(sessionBuf, 16, 0, 16);
    return hexStr;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        { "deriveSessionKeyBridge", nullptr, DeriveSessionKeyRisky, nullptr, nullptr, nullptr, napi_default, nullptr }
    };
    napi_define_properties(env, exports, 1, desc);
    return exports;
}
