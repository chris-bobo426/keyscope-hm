cmake_minimum_required(VERSION 3.16)
project(F2_v4_branch_naming_B_Risky)
add_library(hmcrypto SHARED napi_crypto.cpp)
target_link_libraries(hmcrypto PUBLIC libace_napi.z.so libhilog_ndk.z.so)
