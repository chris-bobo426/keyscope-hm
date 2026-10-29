/**
 * core-ts/bridge/napi_bridge.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 跨语言 NAPI 注册表映射、d.ts 对齐与 Native 表示摘要实例化器
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execFileSync } from 'child_process';
import {
  Facts,
  SecretClass,
  EncodingKind,
  Container,
  Form,
} from '../repr';
import {
  introduceSecret,
  convertRepr,
  aliasRepr,
  SiteLocation,
} from '../rules/transfer';

export interface NativeCreatedSecret {
  obj: string;
  api: string;
  secretClass: SecretClass;
  unambiguous: boolean;
  form: Form;
  container: Container;
  site: string;
  line: number;
}

export interface NativeParamBinding {
  argIndex: number;
  nativeVar: string;
  semantics: 'copy' | 'alias';
  container: Container;
  line: number;
}

export interface NativeReturnInfo {
  from: string;
  via: string;
  semantics: 'copy' | 'alias';
  op: 'copy' | 'alias' | 'encode';
  targetForm: Form;
  encoding?: EncodingKind;
  targetContainer: Container;
  line: number;
}

export interface AstNodeSummary {
  kind: string;
  spelling: string;
  line: number;
}

export interface NapiFunctionSummary {
  js_name: string;
  cpp_func: string;
  file: string;
  line: number;
  dtsDeclared?: boolean;
  ast_backend?: string;
  ast_nodes?: AstNodeSummary[];
  param_bindings: NativeParamBinding[];
  creates: NativeCreatedSecret[];
  returns: NativeReturnInfo | null;
  zeroized_must: string[];
  partial_path_unzeroized: string[];
  plain_memset: string[];
  unknown_calls: string[];
}

const SECRET_GEN_APIS: Record<
  string,
  { cls: SecretClass; unambig: boolean; outArgIndex: number }
> = {
  RAND_bytes: { cls: 'Session', unambig: false, outArgIndex: 0 },
  EVP_PKEY_derive: { cls: 'Session', unambig: true, outArgIndex: 1 },
  ECDH_compute_key: { cls: 'Session', unambig: true, outArgIndex: 0 },
  HKDF: { cls: 'Session', unambig: true, outArgIndex: 0 },
  PKCS5_PBKDF2_HMAC: { cls: 'Session', unambig: true, outArgIndex: 7 },
  EVP_CipherInit_ex: { cls: 'Session', unambig: true, outArgIndex: 3 },
  HITLS_CRYPT_DeriveKey: { cls: 'Session', unambig: true, outArgIndex: 1 },
  SM4_KeyGen: { cls: 'Session', unambig: false, outArgIndex: 0 },
  DeriveSessionKey: { cls: 'Session', unambig: true, outArgIndex: 0 },
  GenerateSymKeyNative: { cls: 'Session', unambig: false, outArgIndex: 0 },
};

function pickSecretOutArg(args: string[], defaultOutIdx: number): string {
  if (args.length === 0) return 'buf';
  if (defaultOutIdx < args.length) {
    const candidate = args[defaultOutIdx].replace(/^&\s*|\([^)]*\)/g, '').trim();
    if (candidate && !/^\d+$|^sizeof\b|^(?:NULL|nullptr|0)$/i.test(candidate)) {
      return candidate;
    }
  }
  const fallbackIdx = Math.min(defaultOutIdx, args.length - 1);
  const fallback = args[fallbackIdx].replace(/^&\s*|\([^)]*\)/g, '').trim();
  if (fallback && !/^\d+$|^sizeof\b|^(?:NULL|nullptr|0)$/i.test(fallback)) {
    return fallback;
  }
  return (args[0] || 'buf').replace(/^&\s*|\([^)]*\)/g, '').trim();
}

const SAFE_ZEROIZE_APIS = [
  'memset_s',
  'explicit_bzero',
  'OPENSSL_cleanse',
  'sodium_memzero',
  'SecureZeroMemory',
  'volatile_zeroize',
];

const PLAIN_MEMSET_APIS = ['memset', 'bzero'];

/**
 * 解析 index.d.ts 中声明的导出函数名集合
 */
export function parseDtsExports(projectDir: string): Set<string> {
  const exportsSet = new Set<string>();
  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith('.d.ts')) {
        const content = fs.readFileSync(full, 'utf-8');
        const re = /export\s+(?:function|const)\s+([A-Za-z0-9_]+)/g;
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          exportsSet.add(m[1]);
        }
      }
    }
  };
  walk(projectDir);
  return exportsSet;
}

const PYTHON_CANDIDATES = [
  'C:\\Users\\zby\\.local\\bin\\python3.12.exe',
  'D:\\Apps\\Dev\\msys64\\ucrt64\\bin\\python3.exe',
  'python3',
  'python',
];

let resolvedPythonExe: string | null | undefined = undefined;
function getPythonExe(): string | null {
  if (resolvedPythonExe !== undefined) return resolvedPythonExe;
  for (const cand of PYTHON_CANDIDATES) {
    try {
      if (cand.includes('\\') && !fs.existsSync(cand)) continue;
      execFileSync(cand, ['--version'], { stdio: 'ignore', timeout: 2000 });
      resolvedPythonExe = cand;
      return cand;
    } catch {
      // try next
    }
  }
  resolvedPythonExe = null;
  return null;
}

const libclangAstCache = new Map<
  string,
  { astBackend: string; nodesByFunc: Map<string, AstNodeSummary[]> }
>();

function extractAstViaLibclangPy(
  filePath: string,
  cppText: string
): { astBackend: string; nodesByFunc: Map<string, AstNodeSummary[]> } | null {
  const hash = crypto.createHash('sha256').update(cppText).digest('hex');
  if (libclangAstCache.has(hash)) {
    return libclangAstCache.get(hash)!;
  }
  const pyExe = getPythonExe();
  const scriptPath = path.resolve(__dirname, '../../native-py/napi_summarizer.py');
  if (!pyExe || !fs.existsSync(scriptPath)) return null;
  try {
    const stdout = execFileSync(pyExe, [scriptPath, filePath], {
      encoding: 'utf-8',
      timeout: 5000,
    });
    const parsed = JSON.parse(stdout) as Array<{
      cpp_func: string;
      ast_backend?: string;
      ast_nodes?: AstNodeSummary[];
    }>;
    let astBackend = 'libclang';
    const nodesByFunc = new Map<string, AstNodeSummary[]>();
    for (const item of parsed) {
      if (item.ast_backend) astBackend = item.ast_backend;
      if (item.ast_nodes) nodesByFunc.set(item.cpp_func, item.ast_nodes);
    }
    const res = { astBackend, nodesByFunc };
    libclangAstCache.set(hash, res);
    return res;
  } catch {
    return null;
  }
}

/**
 * 解析单个 C/C++ 文件中的 NAPI 注册表与函数摘要（结合 libclang.dll AST 提取与 C++ 数据流摘要）
 */
export function parseCppFileSummaries(
  filePath: string,
  dtsExports: Set<string>
): NapiFunctionSummary[] {
  const cppText = fs.readFileSync(filePath, 'utf-8');
  const regMap = new Map<string, string>(); // cppFunc -> jsName

  // 1. 解析 napi_property_descriptor: {"jsName", nullptr, CppFunc, ...}
  const descRe = /\{\s*"([A-Za-z0-9_]+)"\s*,\s*(?:nullptr|NULL|0)\s*,\s*([A-Za-z0-9_]+)/g;
  let m: RegExpExecArray | null;
  while ((m = descRe.exec(cppText)) !== null) {
    regMap.set(m[2], m[1]);
  }
  // 2. 解析 DECLARE_NAPI_FUNCTION("jsName", CppFunc)
  const macroRe = /DECLARE_NAPI_FUNCTION\s*\(\s*"([A-Za-z0-9_]+)"\s*,\s*([A-Za-z0-9_]+)\s*\)/g;
  while ((m = macroRe.exec(cppText)) !== null) {
    regMap.set(m[2], m[1]);
  }

  // 3. 提取所有 C/C++ 函数体
  const funcRe = /(?:static\s+)?(?:napi_value|void|int|bool|size_t)\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*\{/gm;
  const summaries: NapiFunctionSummary[] = [];

  while ((m = funcRe.exec(cppText)) !== null) {
    const funcName = m[1];
    const startLine = cppText.slice(0, m.index).split('\n').length;
    const braceStart = m.index + m[0].length - 1;
    let depth = 0;
    let endIdx = braceStart;
    while (endIdx < cppText.length) {
      if (cppText[endIdx] === '{') depth++;
      else if (cppText[endIdx] === '}') {
        depth--;
        if (depth === 0) break;
      }
      endIdx++;
    }
    const body = cppText.slice(braceStart + 1, endIdx);
    if ((funcName === 'Init' || funcName === 'RegisterModule') && !body.includes('RAND_bytes')) {
      continue;
    }

    const jsName = regMap.get(funcName) ?? funcName;
    const summary = analyzeCppBody(funcName, jsName, startLine, body, filePath, dtsExports);
    if (
      summary.creates.length > 0 ||
      summary.returns !== null ||
      summary.param_bindings.length > 0 ||
      regMap.has(funcName)
    ) {
      summaries.push(summary);
    }
  }

  if (summaries.length > 0) {
    const clangRes = extractAstViaLibclangPy(filePath, cppText);
    if (clangRes) {
      for (const s of summaries) {
        s.ast_backend = clangRes.astBackend;
        s.ast_nodes = clangRes.nodesByFunc.get(s.cpp_func) ?? [];
      }
    }
  }

  return summaries;
}

function analyzeCppBody(
  funcName: string,
  jsName: string,
  startLine: number,
  body: string,
  filePath: string,
  dtsExports: Set<string>
): NapiFunctionSummary {
  const lines = body.split('\n');
  const creates: NativeCreatedSecret[] = [];
  const paramBindings: NativeParamBinding[] = [];
  const encodedBuffers = new Map<string, { from: string; encoding: EncodingKind }>();
  let returnInfo: NativeReturnInfo | null = null;
  const safeZeroized: string[] = [];
  const plainMemset: string[] = [];
  const partialUnzeroized: string[] = [];
  const unknownCalls: string[] = [];

  const secretBufLines = new Map<string, number>();
  const earlyReturnLines: number[] = [];
  const zeroizeLineMap = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const lineNo = startLine + i;
    const line = lines[i].trim();
    if (!line || line.startsWith('//')) continue;

    // 1. 入参绑定
    const mAbIn = line.match(
      /napi_get_(?:arraybuffer|buffer|typedarray)_info\s*\([^,]+,\s*argv\[(\d+)\]\s*,\s*(?:\([^)]*\))?\s*&?([A-Za-z0-9_]+)/
    );
    if (mAbIn) {
      paramBindings.push({
        argIndex: parseInt(mAbIn[1], 10),
        nativeVar: mAbIn[2],
        semantics: 'alias',
        container: 'NativeHeap',
        line: lineNo,
      });
    }

    const mStrIn = line.match(
      /napi_get_value_string_utf8\s*\([^,]+,\s*argv\[(\d+)\]\s*,\s*([A-Za-z0-9_]+)/
    );
    if (mStrIn) {
      paramBindings.push({
        argIndex: parseInt(mStrIn[1], 10),
        nativeVar: mStrIn[2],
        semantics: 'copy',
        container: 'NativeHeap',
        line: lineNo,
      });
    }

    // 2. Native 秘密生成（依据各密码学 API 的官方输出参数索引提取输出缓冲区）
    for (const [apiName, info] of Object.entries(SECRET_GEN_APIS)) {
      const mGen = line.match(new RegExp(`\\b${apiName}\\s*\\(([^)]*)\\)`));
      if (mGen) {
        const args = mGen[1].split(',').map((s) => s.trim());
        const rawBuf = pickSecretOutArg(args, info.outArgIndex);
        creates.push({
          obj: rawBuf,
          api: apiName,
          secretClass: info.cls,
          unambiguous: info.unambig,
          form: 'Raw',
          container: 'NativeHeap',
          site: `${path.basename(filePath)}:${lineNo}`,
          line: lineNo,
        });
        secretBufLines.set(rawBuf, lineNo);
      }
    }

    // 3. 内部 hex / base64 转换
    const mHex = line.match(
      /(?:ToHex|BytesToHex|HexEncode|FormatHex|snprintf|sprintf)\s*\(\s*([A-Za-z0-9_]+).*?,\s*([A-Za-z0-9_]+)\s*\)/
    );
    if (mHex) {
      const [, dstB, srcB] = mHex;
      if (secretBufLines.has(srcB) || paramBindings.some((p) => p.nativeVar === srcB)) {
        encodedBuffers.set(dstB, { from: srcB, encoding: 'hex' });
      }
    }

    // 4. 提前返回路径检测
    if (/\bif\s*\([^)]*\)\s*\{\s*return\b|\bif\s*\([^)]*\)\s*return\b/.test(line)) {
      if (secretBufLines.size > 0) {
        earlyReturnLines.push(lineNo);
      }
    } else if (line.startsWith('return ') && i < lines.length - 3 && secretBufLines.size > 0) {
      earlyReturnLines.push(lineNo);
    }

    // 5. 清零检测
    for (const safeApi of SAFE_ZEROIZE_APIS) {
      const mZ = line.match(new RegExp(`\\b${safeApi}\\s*\\(\\s*([A-Za-z0-9_]+)`));
      if (mZ) {
        const bvar = mZ[1];
        if (!safeZeroized.includes(bvar)) safeZeroized.push(bvar);
        zeroizeLineMap.set(bvar, lineNo);
      }
    }

    for (const plainApi of PLAIN_MEMSET_APIS) {
      const mPz = line.match(new RegExp(`\\b${plainApi}\\s*\\(\\s*([A-Za-z0-9_]+)`));
      if (mPz) {
        const bvar = mPz[1];
        if (!safeZeroized.includes(bvar) && !plainMemset.includes(bvar)) {
          plainMemset.push(bvar);
        }
      }
    }

    // 6. NAPI 返回转换
    const mRetStr = line.match(
      /napi_create_string_(utf8|latin1|utf16)\s*\([^,]+,\s*(?:\([^)]*\))?\s*([A-Za-z0-9_.()]+)/
    );
    if (mRetStr) {
      const encType = mRetStr[1] as EncodingKind;
      const srcExpr = mRetStr[2].split('.')[0].replace(/\([^)]*\)/g, '');
      let origBuf = srcExpr;
      let encoding: EncodingKind = encType;
      if (encodedBuffers.has(srcExpr)) {
        origBuf = encodedBuffers.get(srcExpr)!.from;
        encoding = encodedBuffers.get(srcExpr)!.encoding;
      } else if (line.toLowerCase().includes('hex')) {
        encoding = 'hex';
      }
      returnInfo = {
        from: origBuf,
        via: `napi_create_string_${encType}`,
        semantics: 'copy',
        op: 'encode',
        targetForm: 'Enc',
        encoding,
        targetContainer: 'ArkString',
        line: lineNo,
      };
    }

    const mRetCopy = line.match(
      /(napi_create_buffer_copy|napi_create_arraybuffer)\s*\([^,]+,\s*[^,]+,\s*(?:\([^)]*\))?\s*&?([A-Za-z0-9_]+)/
    );
    if (mRetCopy) {
      const viaApi = mRetCopy[1];
      let srcBuf = mRetCopy[2];
      if (viaApi === 'napi_create_arraybuffer') {
        const mMc = body.match(new RegExp(`memcpy\\s*\\(\\s*${srcBuf}\\s*,\\s*([A-Za-z0-9_]+)`));
        if (mMc) srcBuf = mMc[1];
      }
      returnInfo = {
        from: srcBuf,
        via: viaApi,
        semantics: 'copy',
        op: 'copy',
        targetForm: 'Raw',
        targetContainer: 'ArkBuffer',
        line: lineNo,
      };
    }

    const mRetExt = line.match(
      /napi_create_external_arraybuffer\s*\([^,]+,\s*(?:\([^)]*\))?\s*([A-Za-z0-9_]+)/
    );
    if (mRetExt) {
      returnInfo = {
        from: mRetExt[1],
        via: 'napi_create_external_arraybuffer',
        semantics: 'alias',
        op: 'alias',
        targetForm: 'Raw',
        targetContainer: 'ArkBuffer',
        line: lineNo,
      };
    }
  }

  // 检查是否存在异常分支早退导致漏清零
  for (const [bvar, createLn] of secretBufLines.entries()) {
    const zLn = zeroizeLineMap.get(bvar);
    if (zLn !== undefined) {
      for (const erLn of earlyReturnLines) {
        if (createLn < erLn && erLn < zLn) {
          partialUnzeroized.push(bvar);
          const idx = safeZeroized.indexOf(bvar);
          if (idx >= 0) safeZeroized.splice(idx, 1);
          break;
        }
      }
    }
  }

  return {
    js_name: jsName,
    cpp_func: funcName,
    file: filePath,
    line: startLine,
    dtsDeclared: dtsExports.size === 0 || dtsExports.has(jsName),
    param_bindings: paramBindings,
    creates,
    returns: returnInfo,
    zeroized_must: safeZeroized,
    partial_path_unzeroized: partialUnzeroized,
    plain_memset: plainMemset,
    unknown_calls: unknownCalls,
  };
}

/**
 * 扫描工程目录下所有 C/C++ 文件，返回 Map<jsFuncName, NapiFunctionSummary>
 */
export function buildProjectNapiSummaries(projectDir: string): Map<string, NapiFunctionSummary> {
  const dtsExports = parseDtsExports(projectDir);
  const summaryMap = new Map<string, NapiFunctionSummary>();

  const skipDirs = new Set([
    'node_modules',
    '.git',
    'oh_modules',
    'test',
    'unittest',
    'third_party',
    'paho.mqtt.c',
    'libcoap-4',
  ]);
  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !skipDirs.has(entry.name)) {
        walk(full);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith('.cpp') || entry.name.endsWith('.cc') || entry.name.endsWith('.c'))
      ) {
        const list = parseCppFileSummaries(full, dtsExports);
        for (const s of list) {
          summaryMap.set(s.js_name, s);
          summaryMap.set(s.cpp_func, s);
        }
      }
    }
  };

  walk(projectDir);
  return summaryMap;
}

/**
 * 在 ArkTS 调用 Native NAPI 函数时，将 NapiFunctionSummary 实例化为 LSR Facts
 */
export function instantiateNapiSummary(
  f: Facts,
  summary: NapiFunctionSummary,
  callLoc: SiteLocation,
  argPtsList: Array<Set<string>>
): Set<string> {
  const localVarToReprs = new Map<string, Set<string>>();

  // 1. 绑定入参
  for (const pb of summary.param_bindings) {
    const callerArgPts = argPtsList[pb.argIndex] ?? new Set<string>();
    const bindLoc: SiteLocation = {
      site: `${path.basename(summary.file)}:${pb.line}`,
      file: summary.file,
      line: pb.line,
      ctx: callLoc.ctx,
      desc: `NAPI param argv[${pb.argIndex}] -> ${pb.nativeVar} (${pb.semantics})`,
    };
    if (pb.semantics === 'alias') {
      const aliased = aliasRepr(f, bindLoc, callerArgPts, 'NativeHeap');
      localVarToReprs.set(pb.nativeVar, aliased);
    } else {
      const copiedId = convertRepr(f, bindLoc, callerArgPts, 'Raw', 'NativeHeap', 'napi');
      localVarToReprs.set(pb.nativeVar, new Set([copiedId]));
    }
  }

  // 2. 创建 Native 内部秘密与表示对象
  for (const c of summary.creates) {
    const createLoc: SiteLocation = {
      site: c.site,
      file: summary.file,
      line: c.line,
      ctx: callLoc.ctx,
      desc: `Native ${c.api}(${c.obj})`,
    };
    const { reprId } = introduceSecret(
      f,
      createLoc,
      c.secretClass,
      c.form,
      c.container,
      c.unambiguous,
      `Native ${c.api} in ${summary.cpp_func}`
    );
    localVarToReprs.set(c.obj, new Set([reprId]));

    // 记录 Native 缓冲区的清零状态
    if (summary.zeroized_must.includes(c.obj)) {
      f.zeroizedMust.add(reprId);
    }
    if (summary.partial_path_unzeroized.includes(c.obj)) {
      f.partialPathUnzeroized.add(reprId);
    }
    if (summary.plain_memset.includes(c.obj)) {
      f.plainMemset.add(reprId);
    }
  }

  // 2b. 若入参别名在 Native 中被清零，同步标记
  for (const zVar of summary.zeroized_must) {
    const bound = localVarToReprs.get(zVar);
    if (bound) {
      for (const rId of bound) f.zeroizedMust.add(rId);
    }
  }

  // 3. 处理返回值转换
  if (!summary.returns) {
    return new Set<string>();
  }

  const ret = summary.returns;
  const srcPts = localVarToReprs.get(ret.from) ?? new Set<string>();
  const retLoc: SiteLocation = {
    site: `${path.basename(summary.file)}:${ret.line}`,
    file: summary.file,
    line: ret.line,
    ctx: callLoc.ctx,
    desc: `NAPI return via ${ret.via} (${ret.semantics})`,
  };

  if (ret.semantics === 'alias') {
    // 如 napi_create_external_arraybuffer：共享同一表示对象
    return aliasRepr(f, retLoc, srcPts, ret.targetContainer);
  } else {
    // 如 napi_create_string_utf8 或 napi_create_buffer_copy：创建新表示对象副本
    const retReprId = convertRepr(
      f,
      retLoc,
      srcPts,
      ret.targetForm,
      ret.targetContainer,
      ret.op === 'encode' ? 'encode' : 'napi',
      {
        encoding: ret.encoding,
        uncertain: summary.unknown_calls.length > 0,
      }
    );
    return new Set([retReprId]);
  }
}
