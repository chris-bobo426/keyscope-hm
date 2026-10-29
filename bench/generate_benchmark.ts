/**
 * bench/generate_benchmark.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— HarmonyKeyRepBench 成对差分基准生成器
 *
 * 生成 8 大能力组 (F1–F8) × 4 种代码结构变体 (v1_direct, v2_helper, v3_field, v4_branch_naming) × 2 (A 安全版 / B 风险版)
 * 共计 64 个标准鸿蒙混合工程样本，并输出 bench/benchmark_manifest.json。
 */

import * as fs from 'fs';
import * as path from 'path';

export interface BenchmarkCaseMeta {
  id: string;
  family: 'F1' | 'F2' | 'F3' | 'F4' | 'F5' | 'F6' | 'F7' | 'F8';
  familyName: string;
  variant: 'v1_direct' | 'v2_helper' | 'v3_field' | 'v4_branch_naming';
  pairRole: 'A_Safe' | 'B_Risky';
  expectedVulnerable: boolean;
  expectedRules: string[];
  projectDir: string;
  description: string;
  testedCapability: string;
}

const BENCH_ROOT = path.resolve(__dirname, 'samples');

function writeHarmonyProjectFiles(
  caseDir: string,
  caseId: string,
  etsCode: string,
  cppCode?: string,
  dtsCode?: string
): void {
  const etsDir = path.join(caseDir, 'entry', 'src', 'main', 'ets');
  fs.mkdirSync(etsDir, { recursive: true });
  fs.writeFileSync(path.join(etsDir, 'CryptoService.ets'), etsCode, 'utf-8');

  const ohPkg = {
    name: caseId.toLowerCase(),
    version: '1.0.0',
    description: `HarmonyKeyRepBench sample ${caseId}`,
    main: 'entry/src/main/ets/CryptoService.ets',
    dependencies: cppCode ? { 'libhmcrypto.so': 'file:./entry/src/main/cpp/types/libhmcrypto' } : {},
  };
  fs.writeFileSync(path.join(caseDir, 'oh-package.json5'), JSON.stringify(ohPkg, null, 2), 'utf-8');

  if (cppCode) {
    const cppDir = path.join(caseDir, 'entry', 'src', 'main', 'cpp');
    const typesDir = path.join(cppDir, 'types', 'libhmcrypto');
    fs.mkdirSync(typesDir, { recursive: true });
    fs.writeFileSync(path.join(cppDir, 'napi_crypto.cpp'), cppCode, 'utf-8');
    fs.writeFileSync(
      path.join(cppDir, 'CMakeLists.txt'),
      `cmake_minimum_required(VERSION 3.16)\nproject(${caseId})\nadd_library(hmcrypto SHARED napi_crypto.cpp)\ntarget_link_libraries(hmcrypto PUBLIC libace_napi.z.so libhilog_ndk.z.so)\n`,
      'utf-8'
    );
    fs.writeFileSync(
      path.join(typesDir, 'index.d.ts'),
      dtsCode ?? `export function invokeNativeCrypto(): string | ArrayBuffer;\n`,
      'utf-8'
    );
  }
}

function wrapVariantStructure(
  variant: BenchmarkCaseMeta['variant'],
  coreInitLines: string,
  coreTransformLines: string,
  coreSinkLines: string,
  extraMethods = ''
): string {
  const imports = `import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';
`;

  if (variant === 'v1_direct') {
    return `${imports}
export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
${coreInitLines}
${coreTransformLines}
${coreSinkLines}
  }
${extraMethods}
}
`;
  } else if (variant === 'v2_helper') {
    return `${imports}
export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
${coreTransformLines}
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
${coreSinkLines}
  }

  public executeTask(pref: preferences.Preferences): void {
${coreInitLines}
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }
${extraMethods}
}
`;
  } else if (variant === 'v3_field') {
    return `${imports}
export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
${coreInitLines}
${coreTransformLines}
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
${coreSinkLines}
  }
${extraMethods}
}
`;
  } else {
    // v4_branch_naming: 混淆命名 + 条件分支
    return `${imports}
export class CryptoService {
  public executeTask(pref: preferences.Preferences, modeFlag: boolean): void {
    // 故意使用反向混淆变量名测试是否依赖命名启发式 (打穿 B0)
${coreInitLines}
    let branchHolder: Object = payload;
    if (modeFlag) {
      branchHolder = payload;
    }
    payload = branchHolder as any;
${coreTransformLines}
${coreSinkLines}
  }
${extraMethods}
}
`;
  }
}

export function generateAllBenchmarks(): BenchmarkCaseMeta[] {
  if (fs.existsSync(BENCH_ROOT)) {
    fs.rmSync(BENCH_ROOT, { recursive: true, force: true });
  }
  fs.mkdirSync(BENCH_ROOT, { recursive: true });

  const variants: BenchmarkCaseMeta['variant'][] = [
    'v1_direct',
    'v2_helper',
    'v3_field',
    'v4_branch_naming',
  ];
  const manifest: BenchmarkCaseMeta[] = [];

  for (const v of variants) {
    // =========================================================================
    // F1: 句柄 vs 材料 (Handle vs Key Material in Storage)
    // =========================================================================
    {
      const idA = `F1_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      // 故意在安全版里把 HUKS 别名变量命名为 secretKeyMaterial_8f9a2b3c4d5e6f01 以测试 B0 误报
      const etsA = wrapVariantStructure(
        v,
        `    let secretKeyMaterial_8f9a2b3c4d5e6f01 = 'huks_sm4_key_alias_9f8e7d6c5b4a3f2e';
    huks.generateKeyItem(secretKeyMaterial_8f9a2b3c4d5e6f01, new Object());
    let payload = secretKeyMaterial_8f9a2b3c4d5e6f01;`,
        `    let outPayload = payload;`,
        `    pref.putSync('saved_key_ref', outPayload);`
      );
      writeHarmonyProjectFiles(dirA, idA, etsA);
      manifest.push({
        id: idA,
        family: 'F1',
        familyName: '句柄与密钥材料区分',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '将 HUKS 密钥别名 (KeyHandle) 存入 Preferences，即便变量名为 secretKeyMaterial 也不应误报',
        testedCapability: '区分 Handle 与 KeyMaterial',
      });

      const idB = `F1_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      // 故意在风险版里把真密钥变量命名为 publicConfigAlias 以测试 B0 漏报
      const etsB = wrapVariantStructure(
        v,
        `    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let publicConfigAlias = symGen.generateSymKeySync();
    let encodedBlob = publicConfigAlias.getEncoded();
    let payload = encodedBlob.data;`,
        `    let b64Helper = new util.Base64Helper();
    let outPayload = b64Helper.encodeToStringSync(payload);`,
        `    pref.putSync('saved_key_ref', outPayload);`
      );
      writeHarmonyProjectFiles(dirB, idB, etsB);
      manifest.push({
        id: idB,
        family: 'F1',
        familyName: '句柄与密钥材料区分',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V1', 'V2'],
        projectDir: dirB,
        description: '将 getEncoded() 导出的密钥字节经 Base64 编码后存入 Preferences（变量名伪装为 publicConfigAlias）',
        testedCapability: '区分 Handle 与 KeyMaterial',
      });
    }

    // =========================================================================
    // F2: NAPI 跨语言表示转换 (NAPI Copy Buffer vs Stringification)
    // =========================================================================
    {
      const idA = `F2_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const cppA = `#include <napi/native_api.h>
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
`;
      const etsA = `import hmcrypto from 'libhmcrypto.so';\n` + wrapVariantStructure(
        v,
        `    let rawBuf = hmcrypto.deriveSessionKeyBridge();
    let payload = new Uint8Array(rawBuf);`,
        `    let outPayload = payload;`,
        `    let cipher = cryptoFramework.createCipher('SM4_128|CBC|PKCS7');
    outPayload.fill(0);`
      );
      writeHarmonyProjectFiles(
        dirA,
        idA,
        etsA,
        cppA,
        `export function deriveSessionKeyBridge(): ArrayBuffer;\n`
      );
      manifest.push({
        id: idA,
        family: 'F2',
        familyName: 'NAPI 跨语言表示转换',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: 'Native RAND_bytes 生成密钥后经 napi_create_buffer_copy 传回受控缓冲区，双端执行 memset_s 与 fill(0) 清零',
        testedCapability: '跨语言 NAPI 表示摘要与受控容器判定',
      });

      const idB = `F2_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const cppB = `#include <napi/native_api.h>
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
`;
      const etsB = `import hmcrypto from 'libhmcrypto.so';\n` + wrapVariantStructure(
        v,
        `    let nativeStr = hmcrypto.deriveSessionKeyBridge();
    let payload = nativeStr;`,
        `    let outPayload = payload;`,
        `    let usedLen = outPayload;`
      );
      writeHarmonyProjectFiles(
        dirB,
        idB,
        etsB,
        cppB,
        `export function deriveSessionKeyBridge(): string;\n`
      );
      manifest.push({
        id: idB,
        family: 'F2',
        familyName: 'NAPI 跨语言表示转换',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V1'],
        projectDir: dirB,
        description: 'Native 密钥经 ToHex 与 napi_create_string_utf8 跨语言转换为不可控擦除的 ArkTS String',
        testedCapability: '跨语言 NAPI 表示摘要与受控容器判定',
      });
    }

    // =========================================================================
    // F3: 包装密钥可恢复性不动点 (Wrapped Key Recoverability Fixpoint)
    // =========================================================================
    {
      const idA = `F3_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const etsA = wrapVariantStructure(
        v,
        `    let huksKekAlias = 'huks_master_kek_alias';
    huks.generateKeyItem(huksKekAlias, new Object());
    pref.putSync('kek_reference', huksKekAlias);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, huksKekAlias);
    sessionRaw.fill(0);`,
        `    let outPayload = payload;`,
        `    pref.putSync('wrapped_session_key', outPayload);`
      );
      writeHarmonyProjectFiles(dirA, idA, etsA);
      manifest.push({
        id: idA,
        family: 'F3',
        familyName: '包装密钥可恢复性不动点',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '会话密钥使用 HUKS 硬件绑定密钥包装后存入 Preferences，同域仅存放 HUKS 别名，不可恢复',
        testedCapability: 'Rec(κ, D) 递归可恢复性最小不动点',
      });

      const idB = `F3_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const etsB = wrapVariantStructure(
        v,
        `    // @LongTermSecret
    let kekGen = cryptoFramework.createSymKeyGenerator('AES256');
    let appKekObj = kekGen.generateSymKeySync();
    let appKekBytes = appKekObj.getEncoded().data;
    pref.putSync('co_located_kek_plain', appKekBytes);
    let kdfSpec = cryptoFramework.createKdf('HKDF|SHA256');
    let sessionRaw = kdfSpec.kdfSync(new Object());
    let payload = huks.wrapKey(sessionRaw, appKekBytes);
    sessionRaw.fill(0);`,
        `    let outPayload = payload;`,
        `    pref.putSync('wrapped_session_key', outPayload);`
      );
      writeHarmonyProjectFiles(dirB, idB, etsB);
      manifest.push({
        id: idB,
        family: 'F3',
        familyName: '包装密钥可恢复性不动点',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V2'],
        projectDir: dirB,
        description: '会话密钥虽经包装，但包装它的明文 KEK 被同时存入同一 Preferences (D_store)，导致两者在 D_store 均可恢复',
        testedCapability: 'Rec(κ, D) 递归可恢复性最小不动点',
      });
    }

    // =========================================================================
    // F4: 按秘密身份区分策略与分支汇合 (Per-Secret Policy & Identity Preservation)
    // =========================================================================
    {
      const idA = `F4_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const etsA = wrapVariantStructure(
        v,
        `    let huksKek = 'huks_wrap_alias';
    huks.generateKeyItem(huksKek, new Object());
    // @LongTermSecret
    let ltGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let longTermKey = ltGen.generateSymKeySync();
    let ltRaw = longTermKey.getEncoded().data;
    let wrappedLt = huks.wrapKey(ltRaw, huksKek);
    ltRaw.fill(0);
    let agr = cryptoFramework.createKeyAgreement('X25519');
    let ephemeralSecret = agr.generateSecretSync(new Object(), new Object());
    ephemeralSecret.fill(0);
    let payload = wrappedLt;`,
        `    let outPayload = payload;`,
        `    pref.putSync('long_term_wrapped', outPayload);`
      );
      writeHarmonyProjectFiles(dirA, idA, etsA);
      manifest.push({
        id: idA,
        family: 'F4',
        familyName: '多秘密身份保留与差異化策略',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '长期密钥经 HUKS 包装后落盘，临时协商密钥仅在内存使用并清零',
        testedCapability: '按逻辑秘密 κ 区分生命周期策略与汇合点身份保留',
      });

      const idB = `F4_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const etsB = wrapVariantStructure(
        v,
        `    let huksKek = 'huks_wrap_alias';
    huks.generateKeyItem(huksKek, new Object());
    // @LongTermSecret
    let ltGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let longTermKey = ltGen.generateSymKeySync();
    let ltRaw = longTermKey.getEncoded().data;
    let wrappedLt = huks.wrapKey(ltRaw, huksKek);
    ltRaw.fill(0);
    let agr = cryptoFramework.createKeyAgreement('X25519');
    let ephemeralSecret = agr.generateSecretSync(new Object(), new Object());
    let chosen: Object = wrappedLt;
    if (pref != null) {
      chosen = ephemeralSecret;
    }
    let payload = chosen;`,
        `    let outPayload = payload;`,
        `    pref.putSync('merged_slot', outPayload);`
      );
      writeHarmonyProjectFiles(dirB, idB, etsB);
      manifest.push({
        id: idB,
        family: 'F4',
        familyName: '多秘密身份保留与差异化策略',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V2'],
        projectDir: dirB,
        description: '分支汇合点同时指向已安全包装的长期密钥与未包装的临时会话密钥，随后写入 Preferences',
        testedCapability: '按逻辑秘密 κ 区分生命周期策略与汇合点身份保留',
      });
    }

    // =========================================================================
    // F5: 共用辅助转换函数与上下文敏感 (Shared Helper & 1-Call-Site Context Sensitivity)
    // =========================================================================
    {
      const idA = `F5_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const helperMethod = `
  public toHex(bytes: Uint8Array): string {
    let hexOut = '';
    return hexOut;
  }
`;
      const etsA = wrapVariantStructure(
        v,
        `    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    // 共用辅助函数 toHex 被分别用于公开 IV 与秘密缓冲区的测试调用，但只有 ivHex 被打印日志
    let ivHex = this.toHex(publicIv);
    let unusedCheck = secBytes;
    secBytes.fill(0);
    let payload = ivHex;`,
        `    let outPayload = payload;`,
        `    hilog.info(0x0001, 'CryptoAudit', 'Public IV Hex: %{public}s', outPayload);`,
        helperMethod
      );
      // 为了验证 -Ctx 消融：在另一个只做内部校验但不泄露的方法里调用 this.toHex(secBytesForInternalCheck) OR 在无泄露的分支里调用
      // 等等：如果调用了 this.toHex(secBytes)，就会产生一个 ArkString 表示 (V1)！
      // 在 F5_A_Safe 中，如何让 1-call-site 区分兩個调用点，同时不触发 V1？
      // 看 v3 文档 7.1 节 F5：
      // A（期望不报）：toHex(iv) 写入日志（IV 是公开参数）；同时另一个共用转换函数如 cloneBuffer(iv) vs cloneBuffer(key)！
      // 如果辅助函数是 copyBuffer(buf: Uint8Array): Uint8Array（返回 ArkBuffer，不触发 V1），
      // 在 F5_A_Safe 中：`let ivCopy = this.copyBuffer(publicIv); let keyCopy = this.copyBuffer(secBytes);`
      // 然后 `hilog.info(..., ivCopy)` 或 `pref.putSync('iv', ivCopy)`！
      // 这样：
      // - 在完整版 KeyScope-HM (开启 1-call-site Ctx) 下：`copyBuffer(publicIv)` 返回 `{ρ_iv}`，`copyBuffer(secBytes)` 返回 `{ρ_key}`（随后 `keyCopy.fill(0)`），把 `ivCopy` 写入日志/存储完全不报警（TN）！
      // - 而在 `-Ctx` 消融下：`copyBuffer` 的两个调用点共享同一个 `GLOBAL` 上下文，`copyBuffer` 的返回值合并了 `{ρ_iv, ρ_key}`，导致 `ivCopy` 也被污染了 `κ_key`，写入日志/存储时立即产生误报（FP）！
      const safeHelperMethod = `
  public normalizeBuffer(srcBuf: Uint8Array): Uint8Array {
    let copied = srcBuf.slice();
    return copied;
  }
`;
      const etsA_ctx = wrapVariantStructure(
        v,
        `    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    secBytes.fill(0);
    keyNorm.fill(0);
    let payload = ivNorm;`,
        `    let outPayload = payload;`,
        `    hilog.info(0x0001, 'CryptoAudit', 'Normalized IV: %{public}s', outPayload);`,
        safeHelperMethod
      );
      writeHarmonyProjectFiles(dirA, idA, etsA_ctx);
      manifest.push({
        id: idA,
        family: 'F5',
        familyName: '共用辅助函数上下文敏感',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '公开 IV 与秘密密钥分别调用同一个 normalizeBuffer 辅助函数，仅公开 IV 的返回值写入日志，1-call-site 隔离避免身份串扰',
        testedCapability: '1-call-site 堆克隆上下文敏感 (-Ctx 消融验证)',
      });

      const idB = `F5_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const etsB_ctx = wrapVariantStructure(
        v,
        `    let rand = cryptoFramework.createRandom();
    let publicIv = rand.generateRandomSync(12);
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let secKey = symGen.generateSymKeySync();
    let secBytes = secKey.getEncoded().data;
    let ivNorm = this.normalizeBuffer(publicIv);
    let keyNorm = this.normalizeBuffer(secBytes);
    let payload = keyNorm;`,
        `    let outPayload = payload;`,
        `    hilog.info(0x0001, 'CryptoAudit', 'Leaked Key: %{public}s', outPayload);`,
        safeHelperMethod
      );
      writeHarmonyProjectFiles(dirB, idB, etsB_ctx);
      manifest.push({
        id: idB,
        family: 'F5',
        familyName: '共用辅助函数上下文敏感',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V3'],
        projectDir: dirB,
        description: '秘密密钥经共用辅助函数 normalizeBuffer 转换后被写入 hilog 系统日志',
        testedCapability: '1-call-site 堆克隆上下文敏感 (-Ctx 消融验证)',
      });
    }

    // =========================================================================
    // F6: 单向派生 vs 可逆编码 (OneWay Digest vs Reversible Encoding)
    // =========================================================================
    {
      const idA = `F6_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const etsA = wrapVariantStructure(
        v,
        `    let symGen = cryptoFramework.createSymKeyGenerator('AES256');
    let sessionKey = symGen.generateSymKeySync();
    let rawBytes = sessionKey.getEncoded().data;
    let md = cryptoFramework.createMd('SHA256');
    let fingerprintBlob = md.digestSync(rawBytes);
    rawBytes.fill(0);
    let payload = fingerprintBlob;`,
        `    let outPayload = payload;`,
        `    pref.putSync('key_sha256_fingerprint', outPayload);`
      );
      writeHarmonyProjectFiles(dirA, idA, etsA);
      manifest.push({
        id: idA,
        family: 'F6',
        familyName: '单向派生与可逆编码区分',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '对密钥材料计算 SHA-256 单向摘要 (OneWay) 作为指纹存入 Preferences，不可逆还原原始密钥',
        testedCapability: 'OneWay 不可恢复表示识别 (打穿二元污点 B1)',
      });

      const idB = `F6_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const etsB = wrapVariantStructure(
        v,
        `    let symGen = cryptoFramework.createSymKeyGenerator('AES256');
    let sessionKey = symGen.generateSymKeySync();
    let rawBytes = sessionKey.getEncoded().data;
    let textDec = util.TextDecoder.create('utf-8');
    let reversibleStr = textDec.decodeToString(rawBytes);
    rawBytes.fill(0);
    let payload = reversibleStr;`,
        `    let outPayload = payload;`,
        `    pref.putSync('key_reversible_backup', outPayload);`
      );
      writeHarmonyProjectFiles(dirB, idB, etsB);
      manifest.push({
        id: idB,
        family: 'F6',
        familyName: '单向派生与可逆编码区分',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V1', 'V2'],
        projectDir: dirB,
        description: '将密钥材料通过 TextDecoder 可逆解码为托管字符串并存入 Preferences',
        testedCapability: 'OneWay 不可恢复表示识别 (打穿二元污点 B1)',
      });
    }

    // =========================================================================
    // F7: 结构体字段敏感与 JSON 序列化 (Field-Sensitive Struct & JSON.stringify)
    // =========================================================================
    {
      const idA = `F7_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const etsA = wrapVariantStructure(
        v,
        `    let keyAlias = 'huks_auth_token_alias';
    huks.generateKeyItem(keyAlias, new Object());
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let tempKey = symGen.generateSymKeySync();
    let tempBytes = tempKey.getEncoded().data;
    tempBytes.fill(0);
    let metaObj: Record<string, Object> = new Object() as Record<string, Object>;
    metaObj.handleRef = keyAlias;
    let payload = metaObj;`,
        `    let outPayload = JSON.stringify(payload);`,
        `    pref.putSync('serialized_meta', outPayload);`
      );
      writeHarmonyProjectFiles(dirA, idA, etsA);
      manifest.push({
        id: idA,
        family: 'F7',
        familyName: '结构体字段敏感与序列化',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: '对象字段仅包含 HUKS 密钥别名句柄，经 JSON.stringify 序列化后存入 Preferences',
        testedCapability: '字段敏感指向 (fld) 与 JSON.stringify 递归检查',
      });

      const idB = `F7_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const etsB = wrapVariantStructure(
        v,
        `    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let tempKey = symGen.generateSymKeySync();
    let tempBytes = tempKey.getEncoded().data;
    let secretContainer: Record<string, Object> = new Object() as Record<string, Object>;
    secretContainer.rawKeyField = tempBytes;
    let payload = secretContainer;`,
        `    let outPayload = JSON.stringify(payload);`,
        `    pref.putSync('serialized_meta', outPayload);`
      );
      writeHarmonyProjectFiles(dirB, idB, etsB);
      manifest.push({
        id: idB,
        family: 'F7',
        familyName: '结构体字段敏感与序列化',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['V1', 'V2'],
        projectDir: dirB,
        description: '对象字段包含导出的明文密钥字节，经 JSON.stringify 序列化为字符串后存入 Preferences',
        testedCapability: '字段敏感指向 (fld) 与 JSON.stringify 递归检查',
      });
    }

    // =========================================================================
    // F8 (扩展 E1): NAPI 拷贝 vs 别名清零语义 (Copy vs Alias Zeroization)
    // =========================================================================
    {
      const idA = `F8_${v}_A_Safe`;
      const dirA = path.join(BENCH_ROOT, idA);
      const cppA = `#include <napi/native_api.h>
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
`;
      const etsA = `import hmcrypto from 'libhmcrypto.so';\n` + wrapVariantStructure(
        v,
        `    let extAb = hmcrypto.acquireKeyBuffer();
    let payload = extAb;`,
        `    let outPayload = payload;`,
        `    // 对 external_arraybuffer 别名调用 fill(0) 即同步清零了底层共享原件
    outPayload.fill(0);`
      );
      writeHarmonyProjectFiles(
        dirA,
        idA,
        etsA,
        cppA,
        `export function acquireKeyBuffer(): Uint8Array;\n`
      );
      manifest.push({
        id: idA,
        family: 'F8',
        familyName: 'NAPI 拷贝与别名清零区分',
        variant: v,
        pairRole: 'A_Safe',
        expectedVulnerable: false,
        expectedRules: [],
        projectDir: dirA,
        description: 'Native 通过 napi_create_external_arraybuffer 导出共享内存别名，ArkTS 侧调用 fill(0) 即可清零底层原件',
        testedCapability: 'NAPI Copy vs Alias 语义与 Must-Zeroization (-CopyAlias 消融验证)',
      });

      const idB = `F8_${v}_B_Risky`;
      const dirB = path.join(BENCH_ROOT, idB);
      const cppB = `#include <napi/native_api.h>
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
`;
      const etsB = `import hmcrypto from 'libhmcrypto.so';\n` + wrapVariantStructure(
        v,
        `    let copyAb = hmcrypto.acquireKeyBuffer();
    let payload = copyAb;`,
        `    let outPayload = payload;`,
        `    // 仅清零了 ArkTS 副本，Native 原件因使用普通 memset 在 -O2 下被消除而残留
    outPayload.fill(0);`
      );
      writeHarmonyProjectFiles(
        dirB,
        idB,
        etsB,
        cppB,
        `export function acquireKeyBuffer(): Uint8Array;\n`
      );
      manifest.push({
        id: idB,
        family: 'F8',
        familyName: 'NAPI 拷贝与别名清零区分',
        variant: v,
        pairRole: 'B_Risky',
        expectedVulnerable: true,
        expectedRules: ['E1_M4'],
        projectDir: dirB,
        description: 'Native 通过 napi_create_buffer_copy 返回副本且原件使用可被编译器优化的普通 memset，ArkTS 清零副本无法清零原件',
        testedCapability: 'NAPI Copy vs Alias 语义与 Must-Zeroization (-CopyAlias 消融验证)',
      });
    }
  }

  const manifestPath = path.resolve(__dirname, 'benchmark_manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
  return manifest;
}

if (require.main === module) {
  const cases = generateAllBenchmarks();
  console.log(`[HarmonyKeyRepBench] Generated ${cases.length} paired benchmark projects in ${BENCH_ROOT}`);
}
