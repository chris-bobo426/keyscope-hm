#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
native-py/napi_summarizer.py
鸿钥卫士 KeyScope-HM v3.0 —— 基于 libclang.dll (Clang 15.0.4 C API) 的 Native C/C++ NAPI 表示摘要生成器

核心能力：
1. 通过 ctypes 加载本机 libclang.dll (D:/Apps/Dev/cangjie/third_party/llvm/bin/libclang.dll)，
   使用 CXUnsavedFile 内存翻译单元与 clang_parseTranslationUnit / clang_visitChildren 遍历真实 Clang AST
   (FunctionDecl / ParmDecl / VarDecl / CallExpr / ReturnStmt / IfStmt)；
2. 精确按各密码 API 官方签名定位输出缓冲区参数索引：
   - EVP_PKEY_derive(ctx, out, &len) -> out_arg_index = 1
   - PKCS5_PBKDF2_HMAC(..., keylen, out) -> out_arg_index = 7
   - EVP_CipherInit_ex(ctx, type, impl, key, iv, enc) -> out_arg_index = 3
   - HITLS_CRYPT_DeriveKey(ctx, out, outLen) -> out_arg_index = 1
   - RAND_bytes(buf, len) / ECDH_compute_key(out, ...) / HKDF(out, ...) -> out_arg_index = 0
3. 区分 NAPI 拷贝 (napi_create_buffer_copy / napi_create_string_utf8) 与别名 (napi_create_external_arraybuffer / napi_get_arraybuffer_info)；
4. 提取控制流退出路径上的安全清零 (memset_s / explicit_bzero / OPENSSL_cleanse) 与易被 DSE 消除的普通 memset。
"""

import os
import re
import sys
import json
import ctypes
import argparse
from typing import Dict, List, Any, Optional, Tuple

LIBCLANG_DLL_Candidates = [
    r"D:\Apps\Dev\cangjie\third_party\llvm\bin\libclang.dll",
    r"C:\Program Files\LLVM\bin\libclang.dll",
]
MINGW_INCLUDE_DIR = r"D:\Apps\Dev\msys64\ucrt64\include"

# (secretClass, unambiguous, outArgIndex)
SECRET_GEN_APIS: Dict[str, Tuple[str, bool, int]] = {
    "RAND_bytes": ("Session", False, 0),
    "EVP_PKEY_derive": ("Session", True, 1),
    "ECDH_compute_key": ("Session", True, 0),
    "HKDF": ("Session", True, 0),
    "PKCS5_PBKDF2_HMAC": ("Session", True, 7),
    "EVP_CipherInit_ex": ("Session", True, 3),
    "HITLS_CRYPT_DeriveKey": ("Session", True, 1),
    "SM4_KeyGen": ("Session", False, 0),
    "DeriveSessionKey": ("Session", True, 0),
    "GenerateSymKeyNative": ("Session", False, 0),
}

SAFE_ZEROIZE_APIS = {
    "memset_s",
    "explicit_bzero",
    "OPENSSL_cleanse",
    "sodium_memzero",
    "SecureZeroMemory",
    "volatile_zeroize",
}

PLAIN_MEMSET_APIS = {"memset", "bzero"}


class CXString(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("private_flags", ctypes.c_uint)]


class CXCursor(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int),
        ("xdata", ctypes.c_int),
        ("data", ctypes.c_void_p * 3),
    ]


class CXSourceLocation(ctypes.Structure):
    _fields_ = [("ptr_data", ctypes.c_void_p * 2), ("int_data", ctypes.c_uint)]


class CXUnsavedFile(ctypes.Structure):
    _fields_ = [
        ("Filename", ctypes.c_char_p),
        ("Contents", ctypes.c_char_p),
        ("Length", ctypes.c_ulong),
    ]


VISIT_CB = ctypes.CFUNCTYPE(ctypes.c_int, CXCursor, CXCursor, ctypes.c_void_p)


class LibClangAstExtractor:
    """使用 ctypes 直接调用 libclang.dll 提取 C/C++ 源码的真实 AST 节点"""

    def __init__(self) -> None:
        self.lib = None
        self.version_str = "unavailable"
        for cand in LIBCLANG_DLL_Candidates:
            if os.path.exists(cand):
                try:
                    dll_dir = os.path.dirname(cand)
                    if hasattr(os, "add_dll_directory"):
                        os.add_dll_directory(dll_dir)
                    self.lib = ctypes.CDLL(cand)
                    self._bind_signatures()
                    v = self.lib.clang_getClangVersion()
                    self.version_str = self._cstr(v)
                    break
                except Exception:
                    self.lib = None

    def _bind_signatures(self) -> None:
        assert self.lib is not None
        self.lib.clang_createIndex.argtypes = [ctypes.c_int, ctypes.c_int]
        self.lib.clang_createIndex.restype = ctypes.c_void_p
        self.lib.clang_disposeIndex.argtypes = [ctypes.c_void_p]
        self.lib.clang_parseTranslationUnit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_char_p),
            ctypes.c_int,
            ctypes.POINTER(CXUnsavedFile),
            ctypes.c_uint,
            ctypes.c_uint,
        ]
        self.lib.clang_parseTranslationUnit.restype = ctypes.c_void_p
        self.lib.clang_disposeTranslationUnit.argtypes = [ctypes.c_void_p]
        self.lib.clang_getTranslationUnitCursor.argtypes = [ctypes.c_void_p]
        self.lib.clang_getTranslationUnitCursor.restype = CXCursor
        self.lib.clang_getCursorSpelling.argtypes = [CXCursor]
        self.lib.clang_getCursorSpelling.restype = CXString
        self.lib.clang_getCursorKindSpelling.argtypes = [ctypes.c_int]
        self.lib.clang_getCursorKindSpelling.restype = CXString
        self.lib.clang_getCursorLocation.argtypes = [CXCursor]
        self.lib.clang_getCursorLocation.restype = CXSourceLocation
        self.lib.clang_getExpansionLocation.argtypes = [
            CXSourceLocation,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        self.lib.clang_getClangVersion.restype = CXString
        self.lib.clang_getCString.argtypes = [CXString]
        self.lib.clang_getCString.restype = ctypes.c_char_p
        self.lib.clang_disposeString.argtypes = [CXString]
        self.lib.clang_visitChildren.argtypes = [CXCursor, VISIT_CB, ctypes.c_void_p]

    def _cstr(self, cx_str: CXString) -> str:
        if not self.lib:
            return ""
        raw = self.lib.clang_getCString(cx_str)
        val = raw.decode("utf-8", errors="ignore") if raw else ""
        self.lib.clang_disposeString(cx_str)
        return val

    def parse_ast_nodes(self, cpp_text: str) -> List[Dict[str, Any]]:
        if not self.lib:
            return []
        # 将缺失的外部 NAPI/OpenSSL 头文件替换为等行数的轻量前置声明，确保行号 1:1 严格对齐且 AST 完整生成
        stub_header = (
            "typedef unsigned char uint8_t; typedef unsigned long long size_t; "
            "typedef struct napi_env__* napi_env; typedef struct napi_value__* napi_value; "
            "typedef struct napi_callback_info__* napi_callback_info; "
            "typedef struct EVP_PKEY_CTX_st EVP_PKEY_CTX; "
            "typedef struct { const char* utf8name; const char* name; void* method; void* getter; void* setter; void* value; int attributes; void* data; } napi_property_descriptor; "
            "enum { napi_default = 0 }; const size_t NAPI_AUTO_LENGTH = (size_t)-1; "
            "extern \"C\" { int RAND_bytes(void*, int); int EVP_PKEY_derive(void*, void*, size_t*); "
            "int napi_create_buffer_copy(void*, size_t, const void*, void**, void*); "
            "int napi_create_string_utf8(void*, const char*, size_t, void*); "
            "int napi_create_external_arraybuffer(void*, void*, size_t, void*, void*, void*); "
            "int napi_define_properties(void*, void*, size_t, const void*); "
            "void* memset(void*, int, size_t); int memset_s(void*, size_t, int, size_t); "
            "void ToHex(char*, const void*); }"
        )
        lines = cpp_text.splitlines()
        patched_lines: List[str] = []
        stub_injected = False
        for ln in lines:
            if re.match(r"^\s*#\s*include\b", ln):
                if not stub_injected:
                    patched_lines.append(stub_header.replace("\n", " "))
                    stub_injected = True
                else:
                    patched_lines.append("// include stubbed for standalone AST")
            else:
                patched_lines.append(ln)
        if not stub_injected and patched_lines:
            patched_lines[0] = stub_header.replace("\n", " ") + " " + patched_lines[0]

        code_bytes = "\n".join(patched_lines).encode("utf-8")
        virt_name = b"virtual_napi_unit.cpp"
        uf = CXUnsavedFile(virt_name, code_bytes, len(code_bytes))
        idx = self.lib.clang_createIndex(0, 0)
        args_list = [b"-std=c++17", b"-ferror-limit=0"]
        if os.path.exists(MINGW_INCLUDE_DIR):
            args_list.append(f"-I{MINGW_INCLUDE_DIR}".encode("utf-8"))
        c_args = (ctypes.c_char_p * len(args_list))(*args_list)

        tu = self.lib.clang_parseTranslationUnit(
            idx, virt_name, c_args, len(args_list), ctypes.byref(uf), 1, 0
        )
        if not tu:
            self.lib.clang_disposeIndex(idx)
            return []

        root = self.lib.clang_getTranslationUnitCursor(tu)
        nodes: List[Dict[str, Any]] = []
        target_kinds = {
            "FunctionDecl",
            "ParmDecl",
            "VarDecl",
            "CallExpr",
            "ReturnStmt",
            "IfStmt",
            "InitListExpr",
            "MemberRefExpr",
        }

        def visitor(cursor: CXCursor, _parent: CXCursor, _data: ctypes.c_void_p) -> int:
            kind_str = self._cstr(self.lib.clang_getCursorKindSpelling(cursor.kind))
            if kind_str in target_kinds:
                spelling = self._cstr(self.lib.clang_getCursorSpelling(cursor))
                loc = self.lib.clang_getCursorLocation(cursor)
                line = ctypes.c_uint(0)
                col = ctypes.c_uint(0)
                offset = ctypes.c_uint(0)
                self.lib.clang_getExpansionLocation(
                    loc, None, ctypes.byref(line), ctypes.byref(col), ctypes.byref(offset)
                )
                if not spelling.startswith("__"):
                    nodes.append(
                        {
                            "kind": kind_str,
                            "spelling": spelling,
                            "line": int(line.value),
                            "col": int(col.value),
                        }
                    )
            return 2  # CXChildVisit_Recurse

        self.lib.clang_visitChildren(root, VISIT_CB(visitor), None)
        self.lib.clang_disposeTranslationUnit(tu)
        self.lib.clang_disposeIndex(idx)
        return nodes


GLOBAL_CLANG = LibClangAstExtractor()


def pick_secret_out_arg(args: List[str], default_out_idx: int) -> str:
    if not args:
        return "buf"
    if default_out_idx < len(args):
        cand = re.sub(r"^&\s*|\([^)]*\)", "", args[default_out_idx]).strip()
        if cand and not re.match(r"^\d+$|^sizeof\b|^(?:NULL|nullptr|0)$", cand, re.I):
            return cand
    fallback_idx = min(default_out_idx, len(args) - 1)
    fallback = re.sub(r"^&\s*|\([^)]*\)", "", args[fallback_idx]).strip()
    if fallback and not re.match(r"^\d+$|^sizeof\b|^(?:NULL|nullptr|0)$", fallback, re.I):
        return fallback
    return re.sub(r"^&\s*|\([^)]*\)", "", args[0]).strip() or "buf"


def extract_napi_registrations(cpp_text: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for m in re.finditer(
        r'\{\s*"([A-Za-z0-9_]+)"\s*,\s*(?:nullptr|NULL|0)\s*,\s*([A-Za-z0-9_]+)',
        cpp_text,
    ):
        mapping[m.group(1)] = m.group(2)
    for m in re.finditer(
        r'DECLARE_NAPI_FUNCTION\s*\(\s*"([A-Za-z0-9_]+)"\s*,\s*([A-Za-z0-9_]+)\s*\)',
        cpp_text,
    ):
        mapping[m.group(1)] = m.group(2)
    return mapping


def extract_functions(cpp_text: str) -> List[Tuple[str, int, int, str]]:
    results: List[Tuple[str, int, int, str]] = []
    pattern = re.compile(
        r"(?:static\s+)?(?:napi_value|void|int|bool|size_t)\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    )
    for m in pattern.finditer(cpp_text):
        func_name = m.group(1)
        start_line = cpp_text[: m.start()].count("\n") + 1
        brace_start = m.end() - 1
        depth = 0
        idx = brace_start
        while idx < len(cpp_text):
            ch = cpp_text[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = cpp_text[brace_start + 1 : idx]
                    end_line = start_line + body.count("\n") + 1
                    results.append((func_name, start_line, end_line, body))
                    break
            idx += 1
    return results


def analyze_cpp_function(
    func_name: str,
    start_line: int,
    end_line: int,
    body: str,
    file_path: str,
    js_name: str,
    file_ast_nodes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    lines = body.splitlines()
    created_secrets: List[Dict[str, Any]] = []
    param_bindings: List[Dict[str, Any]] = []
    encoded_buffers: Dict[str, Dict[str, str]] = {}
    return_info: Optional[Dict[str, Any]] = None
    safe_zeroized: List[str] = []
    plain_memset: List[str] = []
    partial_unzeroized: List[str] = []
    unknown_calls: List[str] = []

    secret_buf_lines: Dict[str, int] = {}
    early_return_lines: List[int] = []
    zeroize_line_map: Dict[str, int] = {}

    func_ast_nodes = [
        n for n in file_ast_nodes if start_line <= n.get("line", 0) <= end_line
    ]

    for idx, raw_line in enumerate(lines):
        line_no = start_line + idx
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue

        # 1. 入参绑定
        m_ab_in = re.search(
            r"napi_get_(?:arraybuffer|buffer|typedarray)_info\s*\([^,]+,\s*argv\[(\d+)\]\s*,\s*(?:\([^)]*\))?\s*&?([A-Za-z0-9_]+)",
            line,
        )
        if m_ab_in:
            param_bindings.append(
                {
                    "argIndex": int(m_ab_in.group(1)),
                    "nativeVar": m_ab_in.group(2),
                    "semantics": "alias",
                    "container": "NativeHeap",
                    "line": line_no,
                }
            )

        m_str_in = re.search(
            r"napi_get_value_string_utf8\s*\([^,]+,\s*argv\[(\d+)\]\s*,\s*([A-Za-z0-9_]+)",
            line,
        )
        if m_str_in:
            param_bindings.append(
                {
                    "argIndex": int(m_str_in.group(1)),
                    "nativeVar": m_str_in.group(2),
                    "semantics": "copy",
                    "container": "NativeHeap",
                    "line": line_no,
                }
            )

        # 2. Native 秘密生成 API（按官方签名提取输出参数索引）
        for api_name, (sec_cls, unambig, out_arg_idx) in SECRET_GEN_APIS.items():
            m_gen = re.search(rf"\b{api_name}\s*\(([^)]*)\)", line)
            if m_gen:
                args = [a.strip() for a in m_gen.group(1).split(",")]
                buf_var = pick_secret_out_arg(args, out_arg_idx)
                created_secrets.append(
                    {
                        "obj": buf_var,
                        "api": api_name,
                        "secretClass": sec_cls,
                        "unambiguous": unambig,
                        "form": "Raw",
                        "container": "NativeHeap",
                        "site": f"{os.path.basename(file_path)}:{line_no}",
                        "line": line_no,
                    }
                )
                secret_buf_lines[buf_var] = line_no

        # 3. 内部 hex / base64 转换
        m_hex = re.search(
            r"(?:ToHex|BytesToHex|HexEncode|snprintf|sprintf)\s*\(\s*([A-Za-z0-9_]+).*?,\s*([A-Za-z0-9_]+)\s*\)",
            line,
        )
        if m_hex:
            dst_b, src_b = m_hex.group(1), m_hex.group(2)
            if src_b in secret_buf_lines:
                encoded_buffers[dst_b] = {"from": src_b, "encoding": "hex"}

        # 4. 提前返回分支
        if re.search(r"\bif\s*\([^)]*\)\s*\{\s*return\b|\bif\s*\([^)]*\)\s*return\b", line):
            if secret_buf_lines:
                early_return_lines.append(line_no)
        elif line.startswith("return ") and idx < len(lines) - 2 and secret_buf_lines:
            early_return_lines.append(line_no)

        # 5. 安全清零 vs 普通 memset
        for safe_api in SAFE_ZEROIZE_APIS:
            m_z = re.search(rf"\b{safe_api}\s*\(\s*([A-Za-z0-9_]+)", line)
            if m_z:
                bvar = m_z.group(1)
                if bvar not in safe_zeroized:
                    safe_zeroized.append(bvar)
                zeroize_line_map[bvar] = line_no

        for plain_api in PLAIN_MEMSET_APIS:
            m_pz = re.search(rf"\b{plain_api}\s*\(\s*([A-Za-z0-9_]+)", line)
            if m_pz:
                bvar = m_pz.group(1)
                if bvar not in safe_zeroized and bvar not in plain_memset:
                    plain_memset.append(bvar)

        # 6. NAPI 返回包装方式
        m_ret_str = re.search(
            r"napi_create_string_(utf8|latin1|utf16)\s*\([^,]+,\s*(?:\([^)]*\))?\s*([A-Za-z0-9_.()]+)",
            line,
        )
        if m_ret_str:
            enc_type = m_ret_str.group(1)
            src_expr = m_ret_str.group(2).split(".")[0]
            orig_buf = src_expr
            encoding = enc_type
            if src_expr in encoded_buffers:
                orig_buf = encoded_buffers[src_expr]["from"]
                encoding = encoded_buffers[src_expr]["encoding"]
            elif "hex" in line.lower():
                encoding = "hex"
            return_info = {
                "from": orig_buf,
                "via": f"napi_create_string_{enc_type}",
                "semantics": "copy",
                "op": "encode",
                "targetForm": "Enc",
                "encoding": encoding,
                "targetContainer": "ArkString",
                "line": line_no,
            }

        m_ret_copy = re.search(
            r"(napi_create_buffer_copy|napi_create_arraybuffer)\s*\([^,]+,\s*[^,]+,\s*(?:\([^)]*\))?\s*&?([A-Za-z0-9_]+)",
            line,
        )
        if m_ret_copy:
            via_api = m_ret_copy.group(1)
            src_buf = m_ret_copy.group(2)
            if via_api == "napi_create_arraybuffer":
                m_mc = re.search(
                    r"memcpy\s*\(\s*" + re.escape(src_buf) + r"\s*,\s*([A-Za-z0-9_]+)", body
                )
                if m_mc:
                    src_buf = m_mc.group(1)
            return_info = {
                "from": src_buf,
                "via": via_api,
                "semantics": "copy",
                "op": "copy",
                "targetForm": "Raw",
                "targetContainer": "ArkBuffer",
                "line": line_no,
            }

        m_ret_ext = re.search(
            r"napi_create_external_arraybuffer\s*\([^,]+,\s*(?:\([^)]*\))?\s*([A-Za-z0-9_]+)",
            line,
        )
        if m_ret_ext:
            src_buf = m_ret_ext.group(1)
            return_info = {
                "from": src_buf,
                "via": "napi_create_external_arraybuffer",
                "semantics": "alias",
                "op": "alias",
                "targetForm": "Raw",
                "targetContainer": "ArkBuffer",
                "line": line_no,
            }

    for bvar, create_ln in secret_buf_lines.items():
        z_ln = zeroize_line_map.get(bvar)
        if z_ln is not None:
            for er_ln in early_return_lines:
                if create_ln < er_ln < z_ln:
                    partial_unzeroized.append(bvar)
                    if bvar in safe_zeroized:
                        safe_zeroized.remove(bvar)
                    break

    return {
        "js_name": js_name,
        "cpp_func": func_name,
        "file": file_path,
        "line": start_line,
        "ast_backend": GLOBAL_CLANG.version_str,
        "ast_nodes": func_ast_nodes,
        "param_bindings": param_bindings,
        "creates": created_secrets,
        "returns": return_info,
        "zeroized_must": safe_zeroized,
        "partial_path_unzeroized": partial_unzeroized,
        "plain_memset": plain_memset,
        "unknown_calls": unknown_calls,
    }


def summarize_cpp_file(file_path: str) -> List[Dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        cpp_text = f.read()

    file_ast_nodes = GLOBAL_CLANG.parse_ast_nodes(cpp_text)
    reg_map = extract_napi_registrations(cpp_text)
    cpp_to_js = {v: k for k, v in reg_map.items()}
    funcs = extract_functions(cpp_text)

    summaries: List[Dict[str, Any]] = []
    for func_name, start_line, end_line, body in funcs:
        if func_name in ("Init", "RegisterModule") and "RAND_bytes" not in body:
            continue
        js_name = cpp_to_js.get(func_name, func_name)
        summary = analyze_cpp_function(
            func_name, start_line, end_line, body, file_path, js_name, file_ast_nodes
        )
        if (
            summary["creates"]
            or summary["returns"]
            or summary["param_bindings"]
            or func_name in cpp_to_js
        ):
            summaries.append(summary)
    return summaries


def main() -> None:
    parser = argparse.ArgumentParser(
        description="KeyScope-HM Native C/C++ NAPI Summarizer (libclang AST)"
    )
    parser.add_argument("input_path", help="C/C++ file or project directory")
    parser.add_argument("-o", "--output", help="Output JSON file path", default=None)
    args = parser.parse_args()

    all_summaries: List[Dict[str, Any]] = []
    if os.path.isfile(args.input_path):
        all_summaries.extend(summarize_cpp_file(args.input_path))
    else:
        for root, _, files in os.walk(args.input_path):
            for fn in files:
                if fn.endswith((".cpp", ".cc", ".c", ".cxx")):
                    full_p = os.path.join(root, fn)
                    all_summaries.extend(summarize_cpp_file(full_p))

    out_json = json.dumps(all_summaries, indent=2, ensure_ascii=False)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
    else:
        sys.stdout.buffer.write(out_json.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
