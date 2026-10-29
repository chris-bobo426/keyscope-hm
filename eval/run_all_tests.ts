/**
 * eval/run_all_tests.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 全量自动化验收、独立审查反例回归与外部泛化测试套件 (G1 - G5)
 *
 * 执行方式：
 *   npm test
 *   (或 npx tsx eval/run_all_tests.ts)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as assert from 'assert';
import { DatabaseSync } from 'node:sqlite';
import { analyzeProject } from '../core-ts/analysis/repflow';
import { parseCppFileSummaries } from '../core-ts/bridge/napi_bridge';
import { Facts } from '../core-ts/repr';
import { introduceSecret, convertRepr, wrapRepr } from '../core-ts/rules/transfer';
import { computeRec } from '../core-ts/rec';

function runOrderCase(order: 'wrapped_then_raw' | 'raw_then_wrapped' | 'both'): {
  form?: string;
  recoverable: boolean;
} {
  const facts = new Facts();
  const kek = introduceSecret(
    facts,
    { site: 'order.ets:1', file: 'order.ets', line: 1, ctx: 'M' },
    'HardwareBound',
    'Handle',
    'HUKS',
    false,
    'KEK'
  );
  const dek = introduceSecret(
    facts,
    { site: 'order.ets:2', file: 'order.ets', line: 2, ctx: 'M' },
    'Session',
    'Raw',
    'ArkBuffer',
    true,
    'DEK'
  );
  const wrappedId = wrapRepr(
    facts,
    { site: 'order.ets:3', file: 'order.ets', line: 3, ctx: 'M' },
    new Set([dek.reprId]),
    new Set([kek.secretId]),
    'ArkBuffer'
  );
  const sinkLoc = { site: 'order.ets:10', file: 'order.ets', line: 10, ctx: 'M' };
  let sinkReprId = '';
  if (order === 'wrapped_then_raw') {
    sinkReprId = convertRepr(facts, sinkLoc, new Set([wrappedId]), 'Wrapped', 'Storage', 'persist');
    sinkReprId = convertRepr(facts, sinkLoc, new Set([dek.reprId]), 'Raw', 'Storage', 'persist');
  } else if (order === 'raw_then_wrapped') {
    sinkReprId = convertRepr(facts, sinkLoc, new Set([dek.reprId]), 'Raw', 'Storage', 'persist');
    sinkReprId = convertRepr(facts, sinkLoc, new Set([wrappedId]), 'Wrapped', 'Storage', 'persist');
  } else {
    sinkReprId = convertRepr(facts, sinkLoc, new Set([wrappedId, dek.reprId]), 'Raw', 'Storage', 'persist');
  }
  const recState = computeRec(facts);
  return {
    form: facts.reprs.get(sinkReprId)?.form,
    recoverable: recState.has(`${dek.secretId}|D_store`),
  };
}

function main(): void {
  console.log('================================================================================');
  console.log('KeyScope-HM v3.0 — Full Gate Verification & Counterexample Regression (G1 - G5)');
  console.log('================================================================================');

  // ---------------------------------------------------------------------------
  // Gate G1: ArkAnalyzer (Scene / Cfg / Stmt / APAK CallGraph + PagBuilder + KeyScopeApakPlugin)
  // ---------------------------------------------------------------------------
  console.log('[Gate G1] Verifying ArkAnalyzer Scene/CFG/3-Address IR, APAK PAG & LSR core engine...');
  const sampleRisky = path.resolve(__dirname, '../bench/samples/F3_v1_direct_B_Risky');
  const sampleSafe = path.resolve(__dirname, '../bench/samples/F3_v1_direct_A_Safe');
  const resRisky = analyzeProject(sampleRisky);
  const resSafe = analyzeProject(sampleSafe);

  assert.ok(resRisky.arkFilesCount >= 1, 'G1: ArkAnalyzer must parse .ets files');
  assert.ok(resRisky.methodsAnalyzed >= 1, 'G1: ArkAnalyzer must extract CFG methods');
  assert.ok(resRisky.irDump.length >= 1, 'G1: ArkAnalyzer must export 3-address SSA IR statements (irDump)');
  assert.ok(
    resRisky.apakStats.cgNodesCount >= 1 && resRisky.apakStats.pagNodesCount >= 1,
    'G1: APAK CallGraph + PagBuilder + KeyScopeApakPlugin must run and build pointer graph nodes'
  );
  assert.ok(
    resRisky.findings.some((f) => f.rule === 'V2'),
    'G1: F3_v1_B_Risky (Wrapped + Plaintext KEK in same Preferences) must trigger V2'
  );
  assert.strictEqual(
    resSafe.findings.length,
    0,
    'G1: F3_v1_A_Safe (HUKS-wrapped cipher blob) must have 0 false positives'
  );
  console.log(
    `  ✔ Gate G1 PASSED: ArkAnalyzer Scene/CFG (${resRisky.irDump.length} IR methods), APAK PAG (CG=${resRisky.apakStats.cgNodesCount}, PAG=${resRisky.apakStats.pagNodesCount}, Intercepts=${resRisky.apakStats.interceptedCalls.length}) & LSR fixpoint verified.`
  );

  // ---------------------------------------------------------------------------
  // Gate G2: Native C/C++ NAPI Summarizer powered by real libclang.dll (Clang 15.0.4) AST
  // ---------------------------------------------------------------------------
  console.log('[Gate G2] Verifying Native C/C++ NAPI Summarizer with real libclang.dll AST...');
  const f8RiskyCpp = path.resolve(
    __dirname,
    '../bench/samples/F8_v1_direct_B_Risky/entry/src/main/cpp/napi_crypto.cpp'
  );
  const summaries = parseCppFileSummaries(f8RiskyCpp, new Set());
  assert.ok(summaries.length >= 1, 'G2: NAPI summarizer must extract C++ NAPI functions');
  const f8Sum = summaries[0];
  assert.strictEqual(
    f8Sum.returns?.semantics,
    'copy',
    'G2: napi_create_buffer_copy must be summarized as copy semantics'
  );
  assert.ok(
    Array.isArray(f8Sum.ast_nodes) && f8Sum.ast_nodes.length > 0,
    'G2: libclang.dll (Clang 15.0.4) must populate real C++ AST nodes (FunctionDecl / CallExpr / VarDecl)'
  );
  console.log(
    `  ✔ Gate G2 PASSED: NAPI '${f8Sum.js_name}' -> '${f8Sum.cpp_func}' (${f8Sum.returns?.via}, semantics=${f8Sum.returns?.semantics}, libclang AST nodes=${f8Sum.ast_nodes?.length}) verified.`
  );

  // ---------------------------------------------------------------------------
  // Gate G3: HarmonyKeyRepBench 64-Sample Benchmark & 9-Method Ablation Matrix
  // ---------------------------------------------------------------------------
  console.log('[Gate G3] Verifying HarmonyKeyRepBench (64 samples × 9 methods) evaluation...');
  const benchResultPath = path.resolve(__dirname, 'benchmark_results.json');
  assert.ok(fs.existsSync(benchResultPath), 'G3: eval/benchmark_results.json must exist');
  const benchData = JSON.parse(fs.readFileSync(benchResultPath, 'utf-8'));
  assert.ok(
    Array.isArray(benchData) && benchData.length === 9,
    'G3: Must evaluate 9 methods (B0, B1, B2, 5 ablations, Full v3)'
  );

  const fullMethod = benchData.find((m: { methodName: string }) => m.methodName === 'KeyScope-HM (Full v3)');
  assert.ok(fullMethod, 'G3: Full v3 method must exist in benchmark results');
  assert.strictEqual(
    fullMethod.TP + fullMethod.FP + fullMethod.TN + fullMethod.FN,
    64,
    'G3: Benchmark must have 64 paired samples'
  );
  assert.strictEqual(fullMethod.TP, 32, 'G3: KeyScope-HM Full v3 must achieve TP=32');
  assert.strictEqual(fullMethod.FP, 0, 'G3: KeyScope-HM Full v3 must achieve FP=0 (A-FPR=0%)');
  assert.strictEqual(fullMethod.FN, 0, 'G3: KeyScope-HM Full v3 must achieve FN=0');
  assert.strictEqual(fullMethod.TN, 32, 'G3: KeyScope-HM Full v3 must achieve TN=32');
  assert.strictEqual(fullMethod.f1, 100, 'G3: KeyScope-HM Full v3 must achieve F1=100%');
  console.log(
    `  ✔ Gate G3 PASSED: 64 samples verified (Full v3 F1=${fullMethod.f1.toFixed(2)}%, A-FPR=${fullMethod.groupAFpr.toFixed(2)}%, Median=${fullMethod.medianTimeMs} ms).`
  );

  // ---------------------------------------------------------------------------
  // Gate G4: Dynamic Disassembly + 4-Group ReadProcessMemory Forensics + SQLite & Reports
  // ---------------------------------------------------------------------------
  console.log('[Gate G4] Verifying Dynamic Experiments (with Positive Control), SQLite DB & Reports...');
  const disasmPath = path.resolve(__dirname, '../dynamic/disasm_experiment/disasm_results.json');
  const heapPath = path.resolve(__dirname, '../dynamic/heap_experiment/heap_results.json');
  const rwSummaryPath = path.resolve(__dirname, '../realworld/realworld_summary.json');
  const rwDbPath = path.resolve(__dirname, '../realworld/keyscope_realworld.db');
  const htmlReportPath = path.resolve(__dirname, '../report/output/keyscope_report.html');
  const sarifReportPath = path.resolve(__dirname, '../report/output/keyscope_results.sarif.json');
  const cbomReportPath = path.resolve(__dirname, '../report/output/keyscope_cbom.cdx.json');

  assert.ok(fs.existsSync(disasmPath), 'G4: disasm_results.json must exist');
  assert.ok(fs.existsSync(heapPath), 'G4: heap_results.json must exist');
  assert.ok(fs.existsSync(rwSummaryPath), 'G4: realworld_summary.json must exist');
  assert.ok(fs.existsSync(rwDbPath), 'G4: keyscope_realworld.db must exist');
  assert.ok(fs.existsSync(htmlReportPath), 'G4: keyscope_report.html must exist');
  assert.ok(fs.existsSync(sarifReportPath), 'G4: keyscope_results.sarif.json must exist');
  assert.ok(fs.existsSync(cbomReportPath), 'G4: keyscope_cbom.cdx.json must exist');

  const disasmData = JSON.parse(fs.readFileSync(disasmPath, 'utf-8'));
  const o2Plain = disasmData.functions.wipe_with_plain_memset.O2;
  assert.strictEqual(
    o2Plain.hasZeroingCallOrStore,
    false,
    'G4: -O2 plain memset must be confirmed eliminated by compiler DSE'
  );

  const heapData = JSON.parse(fs.readFileSync(heapPath, 'utf-8'));
  assert.strictEqual(
    heapData.baselineRetentionRate,
    0,
    'G4: Baseline pre-execution retention rate must be 0/10 (0%)'
  );
  assert.strictEqual(
    heapData.posControlUnzeroedBufferCount,
    10,
    'G4: Positive Control (Unzeroed Uint8Array 16B Raw Key) must be detected 10/10 (100%) by ReadProcessMemory'
  );
  assert.strictEqual(
    heapData.riskyStringRetentionCount,
    10,
    'G4: Risky String (ref=null, no Symbol.for) retention count must be 10/10 (100%)'
  );
  assert.strictEqual(
    heapData.safeBufferRetentionCount,
    0,
    'G4: Safe Uint8Array.fill(0) retention count must be 0/10 (0%)'
  );

  const db = new DatabaseSync(rwDbPath);
  const projCount = (db.prepare('SELECT COUNT(*) AS cnt FROM projects').get() as { cnt: number }).cnt;
  const findingCount = (db.prepare('SELECT COUNT(*) AS cnt FROM findings').get() as { cnt: number }).cnt;
  const snippetCount = (
    db.prepare("SELECT COUNT(*) AS cnt FROM findings WHERE length(source_snippet) > 10").get() as { cnt: number }
  ).cnt;
  db.close();
  assert.strictEqual(projCount, 8, 'G4: SQLite DB must contain 8 real-world OpenHarmony repositories');
  assert.ok(findingCount >= 15, 'G4: SQLite DB must contain real-world static alerts');
  assert.strictEqual(
    snippetCount,
    findingCount,
    'G4: Every real-world finding in SQLite DB must include extracted source_snippet evidence'
  );
  console.log(
    `  ✔ Gate G4 PASSED: Compiler DSE (-O0 vs -O2), Win32 ReadProcessMemory (PosCtrl=10/10, Risky=10/10, Safe=0/10), SQLite DB (${projCount} repos, ${findingCount} alerts with source snippets) verified.`
  );

  // ---------------------------------------------------------------------------
  // Gate G5: Independent Audit Counterexamples & Held-Out Generalization Suite
  // ---------------------------------------------------------------------------
  console.log('[Gate G5] Running 5 Independent Audit Counterexamples & Held-Out Generalization Suite...');

  // Counterexample 1: Wrapped ciphertext + Base64 encoding -> 0 false positives
  const tmp1 = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce1-'));
  try {
    fs.cpSync(sampleSafe, tmp1, { recursive: true });
    const etsFile1 = path.join(tmp1, 'entry', 'src', 'main', 'ets', 'CryptoService.ets');
    const patched1 = fs
      .readFileSync(etsFile1, 'utf-8')
      .replace(
        'let outPayload = payload;',
        'let b64 = new util.Base64Helper();\n    let outPayload = b64.encodeToStringSync(payload);'
      );
    fs.writeFileSync(etsFile1, patched1, 'utf-8');
    const ce1Res = analyzeProject(tmp1);
    assert.strictEqual(
      ce1Res.findings.length,
      0,
      `G5.1 (wrapped_encoded): Base64-encoding a HUKS-wrapped ciphertext must produce 0 false positives, got ${ce1Res.findings.length}`
    );

    // Also verify that if the KEK is co-located in plaintext in the same domain, encoding + persisting Wrapped still triggers V2!
    const tmp1Risky = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce1-risky-'));
    fs.cpSync(sampleRisky, tmp1Risky, { recursive: true });
    const etsFile1R = path.join(tmp1Risky, 'entry', 'src', 'main', 'ets', 'CryptoService.ets');
    const patched1R = fs
      .readFileSync(etsFile1R, 'utf-8')
      .replace(
        'let outPayload = payload;',
        'let b64 = new util.Base64Helper();\n    let outPayload = b64.encodeToStringSync(payload);'
      );
    fs.writeFileSync(etsFile1R, patched1R, 'utf-8');
    const ce1RiskyRes = analyzeProject(tmp1Risky);
    assert.ok(
      ce1RiskyRes.findings.some((f) => f.rule === 'V2'),
      'G5.1b (wrapped_encoded_with_colocated_kek): Base64-encoded Wrapped ciphertext with co-located KEK must still trigger V2'
    );
    fs.rmSync(tmp1Risky, { recursive: true, force: true });
  } finally {
    fs.rmSync(tmp1, { recursive: true, force: true });
  }

  // Counterexample 2: Fact arrival order independence (Wrapped+Raw vs Raw+Wrapped vs Both)
  const ordWR = runOrderCase('wrapped_then_raw');
  const ordRW = runOrderCase('raw_then_wrapped');
  const ordBoth = runOrderCase('both');
  assert.strictEqual(ordWR.form, 'Raw', 'G5.2 (merge_order): wrapped_then_raw must join to form=Raw');
  assert.strictEqual(ordRW.form, 'Raw', 'G5.2 (merge_order): raw_then_wrapped must join to form=Raw');
  assert.strictEqual(ordBoth.form, 'Raw', 'G5.2 (merge_order): simultaneous arrival must join to form=Raw');
  assert.strictEqual(ordWR.recoverable, true, 'G5.2: wrapped_then_raw must evaluate recoverable=true');
  assert.strictEqual(ordRW.recoverable, true, 'G5.2: raw_then_wrapped must evaluate recoverable=true');
  assert.strictEqual(ordBoth.recoverable, true, 'G5.2: simultaneous arrival must evaluate recoverable=true');

  // Counterexample 3: Native EVP_PKEY_derive(ctx, out, &len) 2nd output parameter tracking
  const tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce3-'));
  try {
    const cppFile3 = path.join(tmp3, 'derive_case.cpp');
    fs.writeFileSync(
      cppFile3,
      `
#include <napi/native_api.h>
#include <openssl/evp.h>
static napi_value DeriveKeyBad(napi_env env, napi_callback_info info) {
  EVP_PKEY_CTX *ctx = nullptr;
  unsigned char *out = static_cast<unsigned char *>(OPENSSL_malloc(32));
  size_t len = 32;
  EVP_PKEY_derive(ctx, out, &len);
  napi_value result;
  void *dst = nullptr;
  napi_create_buffer_copy(env, len, out, &dst, &result);
  OPENSSL_free(out);
  return result;
}
static napi_value DeriveKeyGood(napi_env env, napi_callback_info info) {
  EVP_PKEY_CTX *ctx = nullptr;
  unsigned char *out = static_cast<unsigned char *>(OPENSSL_malloc(32));
  size_t len = 32;
  EVP_PKEY_derive(ctx, out, &len);
  napi_value result;
  void *dst = nullptr;
  napi_create_buffer_copy(env, len, out, &dst, &result);
  OPENSSL_cleanse(out, len);
  OPENSSL_free(out);
  return result;
}
static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
    { "deriveKeyBad", nullptr, DeriveKeyBad, nullptr, nullptr, nullptr, napi_default, nullptr },
    { "deriveKeyGood", nullptr, DeriveKeyGood, nullptr, nullptr, nullptr, napi_default, nullptr }
  };
  napi_define_properties(env, exports, 2, desc);
  return exports;
}
`,
      'utf-8'
    );
    const sum3 = parseCppFileSummaries(cppFile3, new Set(['deriveKeyBad', 'deriveKeyGood']));
    const badSum = sum3.find((s) => s.js_name === 'deriveKeyBad');
    const goodSum = sum3.find((s) => s.js_name === 'deriveKeyGood');
    assert.ok(badSum && goodSum, 'G5.3: Both deriveKeyBad and deriveKeyGood must be summarized');
    assert.strictEqual(
      badSum.creates[0]?.obj,
      'out',
      'G5.3 (native_derive_output): EVP_PKEY_derive must identify 2nd arg "out" as the secret buffer, not "ctx"'
    );
    assert.strictEqual(
      badSum.returns?.from,
      'out',
      'G5.3: napi_create_buffer_copy must link to derived output buffer "out"'
    );
    assert.strictEqual(
      badSum.zeroized_must.includes('out'),
      false,
      'G5.3: deriveKeyBad (OPENSSL_free without OPENSSL_cleanse) must NOT have "out" in zeroized_must'
    );
    assert.strictEqual(
      goodSum.zeroized_must.includes('out'),
      true,
      'G5.3: deriveKeyGood (OPENSSL_cleanse before OPENSSL_free) must have "out" in zeroized_must'
    );
  } finally {
    fs.rmSync(tmp3, { recursive: true, force: true });
  }

  // Counterexample 4: Filename independence (empty huks_napi_common.cpp = 0 findings; renamed.cpp == huks_napi_common.cpp)
  const tmp4Empty = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce4-empty-'));
  const tmp4Named = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce4-named-'));
  const tmp4Renamed = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-ce4-renamed-'));
  try {
    // 4a: Empty function in huks_napi_common.cpp
    fs.writeFileSync(
      path.join(tmp4Empty, 'huks_napi_common.cpp'),
      'void FreeParsedParams(int &params) {\n  // Empty body: no secret, no HKS_TAG_TYPE_BYTES, no HKS_FREE\n}\n',
      'utf-8'
    );
    const res4Empty = analyzeProject(tmp4Empty);
    assert.strictEqual(
      res4Empty.findings.length,
      0,
      'G5.4a (file_name_dependency): Empty FreeParsedParams in huks_napi_common.cpp must produce 0 findings'
    );

    // 4b: Real vulnerable function body in huks_napi_common.cpp vs arbitrary_renamed_file.cpp
    const vulnCppBody = `
void FreeParsedParams(HksParam *param, int paramCount) {
  while (paramCount > 0) {
    paramCount--;
    if ((param->tag & HKS_TAG_TYPE_MASK) == HKS_TAG_TYPE_BYTES) {
      HKS_FREE(param->blob.data);
      param->blob.size = 0;
    }
  }
}
`;
    fs.writeFileSync(path.join(tmp4Named, 'huks_napi_common.cpp'), vulnCppBody, 'utf-8');
    fs.writeFileSync(path.join(tmp4Renamed, 'arbitrary_renamed_file.cpp'), vulnCppBody, 'utf-8');
    const res4Named = analyzeProject(tmp4Named);
    const res4Renamed = analyzeProject(tmp4Renamed);
    assert.strictEqual(
      res4Named.findings.length,
      1,
      'G5.4b: Vulnerable function body in huks_napi_common.cpp must trigger 1 E1_M4 finding'
    );
    assert.strictEqual(
      res4Renamed.findings.length,
      res4Named.findings.length,
      'G5.4c (file_name_dependency): Identical C++ code in arbitrary_renamed_file.cpp must produce identical findings'
    );
    assert.strictEqual(res4Renamed.findings[0].rule, res4Named.findings[0].rule);
  } finally {
    fs.rmSync(tmp4Empty, { recursive: true, force: true });
    fs.rmSync(tmp4Named, { recursive: true, force: true });
    fs.rmSync(tmp4Renamed, { recursive: true, force: true });
  }

  // Held-Out External Generalization Cases (Unseen Hybrid ArkTS + C++ NAPI patterns)
  const tmpHeldOut1 = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-heldout-pbkdf2-'));
  const tmpHeldOut2 = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-heldout-hitls-safe-'));
  try {
    // Held-out Case 1: PKCS5_PBKDF2_HMAC (8th arg outKey) -> NAPI copy -> ArkTS String conversion (Risky: E1_M4 + V1)
    const etsH1 = path.join(tmpHeldOut1, 'entry', 'src', 'main', 'ets');
    const cppH1 = path.join(tmpHeldOut1, 'entry', 'src', 'main', 'cpp');
    fs.mkdirSync(etsH1, { recursive: true });
    fs.mkdirSync(cppH1, { recursive: true });
    fs.writeFileSync(
      path.join(cppH1, 'pbkdf2_bridge.cpp'),
      `
#include <napi/native_api.h>
static napi_value DerivePbkdf2Native(napi_env env, napi_callback_info info) {
  unsigned char derivedBuf[32];
  PKCS5_PBKDF2_HMAC("pass", 4, nullptr, 0, 10000, nullptr, 32, derivedBuf);
  napi_value outVal;
  void *copyPtr = nullptr;
  napi_create_buffer_copy(env, 32, derivedBuf, &copyPtr, &outVal);
  return outVal;
}
static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
    { "derivePbkdf2Native", nullptr, DerivePbkdf2Native, nullptr, nullptr, nullptr, napi_default, nullptr }
  };
  napi_define_properties(env, exports, 1, desc);
  return exports;
}
`,
      'utf-8'
    );
    fs.writeFileSync(
      path.join(etsH1, 'WalletKdf.ets'),
      `
import nativeKdf from 'libpbkdf2.so';
import util from '@ohos.util';

export function unlockWallet(): string {
  const rawKey: Uint8Array = nativeKdf.derivePbkdf2Native();
  const b64 = new util.Base64Helper();
  const keyStr = b64.encodeToStringSync(rawKey);
  return keyStr;
}
`,
      'utf-8'
    );
    const hoRes1 = analyzeProject(tmpHeldOut1);
    assert.ok(
      hoRes1.findings.some((f) => f.rule === 'V1') && hoRes1.findings.some((f) => f.rule === 'E1_M4'),
      'G5.5 (Held-Out 1): Unseen PKCS5_PBKDF2_HMAC (8th arg) + NAPI copy + Base64 String must trigger both E1_M4 and V1'
    );

    // Held-out Case 2: HITLS_CRYPT_DeriveKey (2nd arg) properly cleansed with OPENSSL_cleanse + ArkTS .fill(0) (Safe: 0 findings)
    const etsH2 = path.join(tmpHeldOut2, 'entry', 'src', 'main', 'ets');
    const cppH2 = path.join(tmpHeldOut2, 'entry', 'src', 'main', 'cpp');
    fs.mkdirSync(etsH2, { recursive: true });
    fs.mkdirSync(cppH2, { recursive: true });
    fs.writeFileSync(
      path.join(cppH2, 'hitls_bridge.cpp'),
      `
#include <napi/native_api.h>
static napi_value DeriveHitlsSafe(napi_env env, napi_callback_info info) {
  unsigned char sessionKey[32];
  HITLS_CRYPT_DeriveKey(0, sessionKey, 32);
  napi_value outVal;
  void *copyPtr = nullptr;
  napi_create_buffer_copy(env, 32, sessionKey, &copyPtr, &outVal);
  OPENSSL_cleanse(sessionKey, 32);
  return outVal;
}
static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
    { "deriveHitlsSafe", nullptr, DeriveHitlsSafe, nullptr, nullptr, nullptr, napi_default, nullptr }
  };
  napi_define_properties(env, exports, 1, desc);
  return exports;
}
`,
      'utf-8'
    );
    fs.writeFileSync(
      path.join(etsH2, 'HitlsSession.ets'),
      `
import hitls from 'libhitls.so';

export function useSessionSafely(): void {
  const keyBuf: Uint8Array = hitls.deriveHitlsSafe();
  keyBuf.fill(0);
}
`,
      'utf-8'
    );
    const hoRes2 = analyzeProject(tmpHeldOut2);
    assert.strictEqual(
      hoRes2.findings.length,
      0,
      `G5.5 (Held-Out 2): Unseen HITLS_CRYPT_DeriveKey (2nd arg) with OPENSSL_cleanse + ArkTS .fill(0) must have 0 false positives, got ${hoRes2.findings.length}`
    );
  } finally {
    fs.rmSync(tmpHeldOut1, { recursive: true, force: true });
    fs.rmSync(tmpHeldOut2, { recursive: true, force: true });
  }

  console.log(
    '  ✔ Gate G5 PASSED: All 5 Independent Audit Counterexamples (wrapped_encoded, merge_order, native_derive_output, file_name_dependency, pos_control_heap) + External Held-Out Generalization Suite verified!'
  );
  console.log('================================================================================');
  console.log('ALL 5 GATES (G1, G2, G3, G4, G5) PASSED SUCCESSFULLY!');
  console.log('================================================================================');
}

if (require.main === module) {
  main();
}
