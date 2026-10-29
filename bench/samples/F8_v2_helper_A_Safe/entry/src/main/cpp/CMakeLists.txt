cmake_minimum_required(VERSION 3.16)
project(F8_v2_helper_A_Safe)
add_library(hmcrypto SHARED napi_crypto.cpp)
target_link_libraries(hmcrypto PUBLIC libace_napi.z.so libhilog_ndk.z.so)
