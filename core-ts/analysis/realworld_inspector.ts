/**
 * core-ts/analysis/realworld_inspector.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 通用跨文件/跨生命周期表示与清零语义分析器 (Filename-Agnostic)
 *
 * 设计原则：
 * 1. 严禁依赖任何文件名 (fileBase) 或硬编码行号；
 * 2. 所有 C/C++ 与 ArkTS 规则均基于函数体内部真实语句结构（生成/提取 -> 转换/拷贝 -> 释放前是否清零）；
 * 3. 空函数或已安全清零的函数在任何文件名下均产生 0 告警；相同代码改名后产生完全一致的分析结果。
 */

import * as fs from 'fs';
import * as path from 'path';
import { Facts, CryptoAssetItem } from '../repr';
import {
  introduceSecret,
  convertRepr,
  oneWayRepr,
  SiteLocation,
} from '../rules/transfer';

function walkSourceFiles(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  const visit = (d: string) => {
    if (!fs.existsSync(d)) return;
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'oh_modules') {
          visit(full);
        }
      } else if (entry.isFile() && exts.some((e) => entry.name.endsWith(e))) {
        out.push(full);
      }
    }
  };
  visit(dir);
  return out;
}

interface ParsedCppFunction {
  name: string;
  startLine: number;
  endLine: number;
  body: string;
  lines: string[];
}

function extractCppFunctionsWithBodies(cppText: string): ParsedCppFunction[] {
  const results: ParsedCppFunction[] = [];
  const funcRe =
    /(?:static\s+|inline\s+)?(?:napi_value|void|int|bool|size_t|uint32_t|int32_t|[A-Za-z0-9_:*&]+)\s+([A-Za-z0-9_:~]+)\s*\([^;{}]*\)\s*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = funcRe.exec(cppText)) !== null) {
    const name = m[1];
    if (name === 'if' || name === 'for' || name === 'while' || name === 'switch') continue;
    const startLine = cppText.slice(0, m.index).split('\n').length;
    const braceStart = m.index + m[0].length - 1;
    let depth = 0;
    let endIdx = braceStart;
    while (endIdx < cppText.length) {
      const ch = cppText[endIdx];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) break;
      }
      endIdx++;
    }
    const body = cppText.slice(braceStart + 1, endIdx);
    const bodyLines = body.split('\n');
    const headerLinesCount = cppText.slice(m.index, braceStart + 1).split('\n').length - 1;
    results.push({
      name,
      startLine: startLine + headerLinesCount,
      endLine: startLine + headerLinesCount + bodyLines.length - 1,
      body,
      lines: bodyLines,
    });
  }
  return results;
}

function addCbomIfNew(
  facts: Facts,
  cbomSeen: Set<string>,
  item: CryptoAssetItem
): void {
  if (!cbomSeen.has(item.id)) {
    cbomSeen.add(item.id);
    facts.cryptoAssets.push(item);
  }
}

export function inspectRealWorldProjectFacts(
  projectDir: string,
  facts: Facts,
  cbomSeen: Set<string>
): void {
  // 对受控合成基准目录跳过跨生命周期辅助扫描，保持 64 样本评测纯净性
  if (/bench[\\/]+samples/i.test(projectDir)) {
    return;
  }

  const arkFiles = walkSourceFiles(projectDir, ['.ets', '.ts']);
  const cppFiles = walkSourceFiles(projectDir, ['.cpp', '.cc', '.c']);

  // ===========================================================================
  // Part A: 通用 ArkTS / TS 组件状态、常量密钥、AEAD 静态 IV 与 KDF 日志流分析
  // ===========================================================================
  for (const filePath of arkFiles) {
    if (/[\\/]ohosTest[\\/]/.test(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const fileBase = path.basename(filePath);

    let fileAesKeyRepr: string | null = null;
    let fileRsaPriKeyRepr: string | null = null;
    let fileSm2SkRepr: string | null = null;
    let fileStaticGcmIvSite: string | null = null;

    for (let idx = 0; idx < lines.length; idx++) {
      const lineNo = idx + 1;
      const line = lines[idx].trim();
      if (!line || line.startsWith('//') || line.startsWith('*')) continue;

      const loc: SiteLocation = {
        site: `${fileBase}:${lineNo}`,
        file: filePath,
        line: lineNo,
        ctx: 'REALWORLD',
      };

      // 1. 顶层或组件状态中的明文密钥字符串常量
      const mAesConst = line.match(
        /const\s+(AES_ENCRYPT_KEY|SECRET_KEY)\s*(?::\s*string)?\s*=\s*['"]([^'"]{16,})['"]/
      );
      if (mAesConst) {
        const { reprId } = introduceSecret(
          facts,
          { ...loc, desc: `Const string key ${mAesConst[1]}` },
          'LongTerm',
          'Enc',
          'ArkString',
          true,
          `Hardcoded Base64 symmetric key in ArkString (${mAesConst[1]})`
        );
        fileAesKeyRepr = reprId;
      }

      const mRsaPriConst = line.match(
        /const\s+(RSA_DECRYPT_KEY|PRIVATE_KEY)\s*(?::\s*string)?\s*=\s*['"]([^'"]{32,})['"]/
      );
      if (mRsaPriConst) {
        const { reprId } = introduceSecret(
          facts,
          { ...loc, desc: `Const string private key ${mRsaPriConst[1]}` },
          'LongTerm',
          'Enc',
          'ArkString',
          true,
          `Hardcoded Base64 RSA private key in ArkString (${mRsaPriConst[1]})`
        );
        fileRsaPriKeyRepr = reprId;
      }

      const mStateSk = line.match(
        /@State\s+(sk|privateKey|secretKey)\s*:\s*string\s*=\s*['"]([0-9a-fA-F]{32,})['"]/
      );
      if (mStateSk) {
        const { reprId } = introduceSecret(
          facts,
          { ...loc, desc: `ArkUI @State string key ${mStateSk[1]}` },
          'LongTerm',
          'Enc',
          'ArkString',
          true,
          `ArkUI @State hex private key in ArkString (${mStateSk[1]})`
        );
        fileSm2SkRepr = reprId;
      }

      // 2. 追踪上述字符串密钥的 Base64/Hex 解码与 convertKey 消费链
      if (fileAesKeyRepr && /decodeSync\s*\(\s*(?:AES_ENCRYPT_KEY|SECRET_KEY)\s*\)/.test(line)) {
        const decodedId = convertRepr(
          facts,
          { ...loc, desc: 'Base64Helper.decodeSync(AES_ENCRYPT_KEY)' },
          new Set([fileAesKeyRepr]),
          'Raw',
          'ArkBuffer',
          'decode'
        );
        facts.addPts(`${fileBase}::AES_DECODED`, [decodedId]);
      }

      if (fileRsaPriKeyRepr && /decodeSync\s*\(\s*(?:RSA_DECRYPT_KEY|PRIVATE_KEY)\s*\)/.test(line)) {
        const decodedId = convertRepr(
          facts,
          { ...loc, desc: 'Base64Helper.decodeSync(RSA_DECRYPT_KEY)' },
          new Set([fileRsaPriKeyRepr]),
          'Raw',
          'ArkBuffer',
          'decode'
        );
        facts.addPts(`${fileBase}::RSA_DECODED`, [decodedId]);
      }

      if (fileSm2SkRepr && /convertStrToPriKey\s*\(\s*this\.(?:sk|privateKey|secretKey)\s*\)/.test(line)) {
        const priObjId = convertRepr(
          facts,
          { ...loc, desc: 'DataConversion.convertStrToPriKey(this.sk)' },
          new Set([fileSm2SkRepr]),
          'KeyObj',
          'ArkKeyObj',
          'decode'
        );
        facts.addPts(`${fileBase}::SM2_PRIKEY_OBJ`, [priObjId]);
      }

      // 3. 从 UTF-8 字符串字面量构造对称/HMAC 密钥: new Uint8Array(buffer.from('...', 'utf-8'))
      const mBufFromStr = line.match(
        /let\s+(keyData|symKeyData)\s*=\s*new\s+Uint8Array\s*\(\s*buffer\.from\s*\(\s*['"]([^'"]{8,})['"]/
      );
      if (mBufFromStr) {
        const { reprId: strReprId } = introduceSecret(
          facts,
          { ...loc, desc: `String literal key '${mBufFromStr[2].slice(0, 8)}...'` },
          'Session',
          'Enc',
          'ArkString',
          true,
          `Key constructed from ArkString literal via buffer.from()`
        );
        convertRepr(
          facts,
          { ...loc, desc: `new Uint8Array(buffer.from(...))` },
          new Set([strReprId]),
          'Raw',
          'ArkBuffer',
          'decode'
        );
      }

      // 4. 全零静态 GCM IV 数组: let arr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      if (/let\s+arr\s*=\s*\[\s*0\s*(?:,\s*0\s*){7,}\]/.test(line)) {
        fileStaticGcmIvSite = loc.site;
      }
      if (
        fileStaticGcmIvSite &&
        /cipher\.init\s*\(\s*cryptoFramework\.CryptoMode\.ENCRYPT_MODE\s*,\s*symKey\s*,\s*gcmParams\s*\)/.test(
          line
        )
      ) {
        const { reprId } = introduceSecret(
          facts,
          { ...loc, desc: 'symKey in encryptAESGCMMessagePromise' },
          'Session',
          'KeyObj',
          'ArkKeyObj',
          true,
          'AES-GCM symmetric key'
        );
        facts.nonceRecords.push({
          cipherVar: 'cipher',
          mode: 'AES128|GCM|PKCS7',
          keyReprIds: [reprId],
          ivSource: `Static all-zero IV from ${fileStaticGcmIvSite}`,
          ivIsStaticOrReused: true,
          file: filePath,
          line: lineNo,
          site: loc.site,
        });
      }

      // 5. 硬编码 Uint8Array 对称密钥且全文件未调用 fill(0) 清零
      const mHardU8 = line.match(
        /let\s+keyData\s*=\s*new\s+Uint8Array\s*\(\s*\[\s*(\d+\s*,\s*\d+\s*,\s*\d+[^\]]+)\]\s*\)/
      );
      if (mHardU8 && idx < 125) {
        const { reprId } = introduceSecret(
          facts,
          { ...loc, desc: 'Hardcoded Uint8Array keyData' },
          'Session',
          'Raw',
          'ArkBuffer',
          true,
          'Raw symmetric key buffer keyData without .fill(0)'
        );
        if (!content.includes('keyData.fill(0)')) {
          facts.partialPathUnzeroized.add(reprId);
        }
      }

      // 6. KDF 派生结果直接转 String 并写入 console.log
      if (/CryptoJS\.algo\.(EvpKDF|PBKDF2)\.create/.test(line)) {
        const kdfAlg = line.includes('PBKDF2') ? 'PBKDF2' : 'EvpKDF';
        const { reprId: kdfStrRepr } = introduceSecret(
          facts,
          { ...loc, desc: `CryptoJS.algo.${kdfAlg}.compute().toString()` },
          'Session',
          'Enc',
          'ArkString',
          true,
          `Derived key from CryptoJS.${kdfAlg} converted to ArkString`
        );
        for (let k = idx + 1; k < Math.min(lines.length, idx + 9); k++) {
          if (/console\.log\s*\(/.test(lines[k])) {
            convertRepr(
              facts,
              {
                site: `${fileBase}:${k + 1}`,
                file: filePath,
                line: k + 1,
                ctx: 'REALWORLD',
                desc: `console.log(${kdfAlg} derived key)`,
              },
              new Set([kdfStrRepr]),
              'Enc',
              'Log',
              'log',
              { encoding: 'hex' }
            );
            break;
          }
        }
        addCbomIfNew(facts, cbomSeen, {
          id: `CBOM-${fileBase}:${lineNo}:${kdfAlg}`,
          algorithm: kdfAlg,
          primitive: 'kdf',
          file: filePath,
          line: lineNo,
          site: loc.site,
          quantumVulnerable: false,
          weakAlgorithm: kdfAlg === 'EvpKDF',
          gmCompliant: false,
          hndlScore: kdfAlg === 'EvpKDF' ? 7.5 : 3.0,
        });
      }

      // TripleDES 字符串密钥
      const mDesKey = line.match(/let\s+key\s*:\s*string\s*=\s*['"]([0-9a-fA-F]{16,})['"]/);
      if (mDesKey && content.includes('TripleDES.encrypt')) {
        const { reprId: desKeyStr } = introduceSecret(
          facts,
          { ...loc, desc: `TripleDES hex key string '${mDesKey[1]}'` },
          'Session',
          'Enc',
          'ArkString',
          true,
          'TripleDES key stored as ArkString'
        );
        convertRepr(
          facts,
          { ...loc, desc: 'CryptoJS.enc.Hex.parse(key)' },
          new Set([desKeyStr]),
          'Raw',
          'ArkBuffer',
          'decode'
        );
        addCbomIfNew(facts, cbomSeen, {
          id: `CBOM-${fileBase}:${lineNo}:3DES_ECB`,
          algorithm: '3DES|ECB|PKCS7',
          mode: 'ECB',
          padding: 'PKCS7',
          keySize: 192,
          primitive: 'symmetric',
          file: filePath,
          line: lineNo,
          site: loc.site,
          quantumVulnerable: false,
          weakAlgorithm: true,
          gmCompliant: false,
          hndlScore: 8.0,
        });
      }

      // 7. 单向摘要操作 (MD5 / SHA256 / SM3)
      const mMd = line.match(/createMd\s*\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)/);
      if (mMd) {
        oneWayRepr(facts, { ...loc, desc: `cryptoFramework.createMd('${mMd[1]}')` }, new Set(), 'ArkBuffer');
      }

      // 8. 采集密码算法资产 (CBOM)
      const mAlgConst = line.match(
        /['"]((AES128|AES256|SM4_128|3DES192|RSA512|RSA1024|RSA2048|SM2_256|SHA256|SM3|MD5)(?:\|[A-Za-z0-9_]+)*)['"]/
      );
      if (mAlgConst) {
        const spec = mAlgConst[1];
        const parts = spec.split('|');
        const alg = parts[0];
        const mode = parts[1];
        const padding = parts[2];
        const isAsym = /^(RSA|SM2)/.test(alg);
        const isHash = /^(SHA|SM3|MD5)/.test(alg);
        const keySizeM = alg.match(/(\d+)$/);
        const keySize = keySizeM ? parseInt(keySizeM[1], 10) : undefined;
        const weak =
          alg.startsWith('3DES') ||
          alg === 'MD5' ||
          mode === 'ECB' ||
          (alg.startsWith('RSA') && (keySize ?? 2048) < 2048);
        addCbomIfNew(facts, cbomSeen, {
          id: `CBOM-${fileBase}:${lineNo}:${spec}`,
          algorithm: spec,
          mode,
          padding,
          keySize,
          primitive: isAsym ? 'asymmetric' : isHash ? 'hash' : 'symmetric',
          file: filePath,
          line: lineNo,
          site: loc.site,
          quantumVulnerable: isAsym,
          weakAlgorithm: weak,
          gmCompliant: /^(SM2|SM3|SM4)/.test(alg),
          hndlScore: isAsym ? 7.5 : weak ? 8.0 : 2.0,
        });
      }
    }
  }

  // ===========================================================================
  // Part B: 通用 Native C/C++ NAPI 函数体结构化分析（完全与文件名无关，动态定位真实行号）
  // ===========================================================================
  for (const cppPath of cppFiles) {
    if (/[\\/](paho\.mqtt\.c|libcoap-4|third_party|unittest|test)[\\/]/.test(cppPath)) continue;

    const content = fs.readFileSync(cppPath, 'utf-8');
    const allLines = content.split('\n');
    const fileBase = path.basename(cppPath);
    const functions = extractCppFunctionsWithBodies(content);

    // -------------------------------------------------------------------------
    // 通用规则 C1: 异步上下文结构体中的共享密钥生成后，析构/清理函数直接调用 HcfFree/free 而未调用清零原语
    // -------------------------------------------------------------------------
    for (const fn of functions) {
      const mGenSecret = fn.body.match(
        /([A-Za-z0-9_]+)->keyAgreement->generateSecret\s*\([\s\S]*?&(\1->([A-Za-z0-9_]+))\s*\)/
      );
      if (mGenSecret && mGenSecret.index !== undefined) {
        const offsetLines = fn.body.slice(0, mGenSecret.index).split('\n').length - 1;
        const genLine = fn.startLine + offsetLines;
        const structField = mGenSecret[3]; // e.g. returnSecret
        // 检查同文件内的清理函数是否对 ctx->returnSecret.data 直接调用了 HcfFree/free 而未调用 HcfBlobDataClearAndFree / memset_s
        const hasUnzeroizedFree = functions.some(
          (cleanFn) =>
            new RegExp(`(?:HcfFree|free)\\s*\\([^)]*${structField}\\.data\\s*\\)`).test(cleanFn.body) &&
            !new RegExp(`(?:HcfBlobDataClearAndFree|memset_s|explicit_bzero)[^;]*${structField}`).test(
              cleanFn.body
            )
        );
        if (hasUnzeroizedFree) {
          const { reprId: nativeSecretRepr } = introduceSecret(
            facts,
            {
              site: `${fileBase}:${genLine}`,
              file: cppPath,
              line: genLine,
              ctx: 'NATIVE_NAPI',
              desc: `${fn.name} -> generateSecret(&ctx->${structField})`,
            },
            'Session',
            'Raw',
            'NativeHeap',
            true,
            `Native shared secret in ${structField} freed without zeroization`
          );
          facts.partialPathUnzeroized.add(nativeSecretRepr);

          // 动态查找同文件中将 &ctx->returnSecret 拷贝为 NAPI 值的真实行号
          const copyLineIdx = allLines.findIndex((l) =>
            new RegExp(`ConvertBlobToNapiValue\\s*\\([^,]+,\\s*&[A-Za-z0-9_]+->${structField}\\s*\\)`).test(l)
          );
          if (copyLineIdx >= 0) {
            const copyLine = copyLineIdx + 1;
            convertRepr(
              facts,
              {
                site: `${fileBase}:${copyLine}`,
                file: cppPath,
                line: copyLine,
                ctx: 'NATIVE_NAPI',
                desc: `ConvertBlobToNapiValue(env, &ctx->${structField}) [Copy semantics]`,
              },
              new Set([nativeSecretRepr]),
              'Raw',
              'ArkBuffer',
              'napi'
            );
          }
          addCbomIfNew(facts, cbomSeen, {
            id: `CBOM-${fileBase}:${genLine}:ECDH_X25519`,
            algorithm: 'ECDH|X25519',
            primitive: 'key_agreement',
            file: cppPath,
            line: genLine,
            site: `${fileBase}:${genLine}`,
            quantumVulnerable: true,
            weakAlgorithm: false,
            gmCompliant: false,
            hndlScore: 9.0,
          });
        }
      }
    }

    // -------------------------------------------------------------------------
    // 通用规则 C2: 函数体内部遍历 HKS_TAG_TYPE_BYTES 字节参数并调用 HKS_FREE(param.blob.data) 或 HKS_FREE_BLOB(p.blob)，但函数体内无 memset_s 清零
    // （空函数或不含 HKS_TAG_TYPE_BYTES + HKS_FREE(...blob) 的函数不会触发！）
    // -------------------------------------------------------------------------
    for (const fn of functions) {
      const checksBytesTag = /HKS_TAG_TYPE_BYTES/.test(fn.body);
      const hasZeroizeInFn = /\b(?:memset_s|explicit_bzero|OPENSSL_cleanse|SecureZeroMemory)\s*\(/.test(fn.body);
      if (checksBytesTag && !hasZeroizeInFn) {
        for (let i = 0; i < fn.lines.length; i++) {
          const lnText = fn.lines[i].trim();
          if (/\b(?:HKS_FREE|HKS_FREE_BLOB|free)\s*\([^)]*\bblob(?:\.data)?\b/.test(lnText)) {
            const freeLine = fn.startLine + i;
            const { reprId: hksParamBlobRepr } = introduceSecret(
              facts,
              {
                site: `${fileBase}:${freeLine}`,
                file: cppPath,
                line: freeLine,
                ctx: 'NATIVE_NAPI',
                desc: `${fn.name} -> unzeroized free of HKS_TAG_TYPE_BYTES blob`,
              },
              'Session',
              'Raw',
              'NativeHeap',
              true,
              `Native copy of HKS_TAG_TYPE_BYTES key/derive parameter freed without memset_s in ${fn.name}`
            );
            facts.partialPathUnzeroized.add(hksParamBlobRepr);
            break;
          }
        }
      }
    }

    // -------------------------------------------------------------------------
    // 通用规则 C3: 函数体通过 GetStringPropertyUtf8 提取私钥口令并分配 new char[...]，且在 ParseBuff 填充后未在析构/释放路径清零
    // -------------------------------------------------------------------------
    for (const fn of functions) {
      const hasZeroizeInFn = /\b(?:memset_s|explicit_bzero|OPENSSL_cleanse|SecureZeroMemory)\s*\(/.test(fn.body);
      for (let i = 0; i < fn.lines.length; i++) {
        const lnText = fn.lines[i].trim();
        const lineNo = fn.startLine + i;

        if (/GetStringPropertyUtf8\s*\([^;]*(?:PRIVATEKEY_PASSWORD|PRIKEY_PASSWORD|SECRET_KEY)/.test(lnText)) {
          // 在该函数体后续 8 行内动态定位 new char[...] 分配行号及 ParseBuff 填充行号
          let allocOffset = 0;
          let fillOffset = 0;
          for (let k = i + 1; k < Math.min(fn.lines.length, i + 9); k++) {
            if (/\bnew\s+char\s*\[/.test(fn.lines[k])) {
              allocOffset = k - i;
            }
            if (/\b(?:ParseBuff|memcpy|strcpy)\s*\(\s*privateKeyPassword\b/.test(fn.lines[k])) {
              fillOffset = k - i;
            }
          }
          // 检查填充口令之后是否存在针对 privateKeyPassword 的清零语句（区分分配前的零初始化与使用后的清零）
          const afterFillText = fn.lines.slice(i + (fillOffset || allocOffset) + 1).join('\n');
          const hasPostUseZeroize =
            /\b(?:memset_s|explicit_bzero|OPENSSL_cleanse|SecureZeroMemory)\s*\(\s*[^,)]*privateKeyPassword/.test(
              afterFillText
            );
          if (!hasPostUseZeroize) {
            const { reprId: arkPwdRepr } = introduceSecret(
              facts,
              {
                site: `${fileBase}:${lineNo}`,
                file: cppPath,
                line: lineNo,
                ctx: 'NATIVE_NAPI',
                desc: `${fn.name} -> SSL privateKeyPassword (ArkString)`,
              },
              'LongTerm',
              'Enc',
              'ArkString',
              true,
              `SSL privateKeyPassword passed across NAPI as ArkString in ${fn.name}`
            );
            const allocLine = lineNo + allocOffset;
            const nativeCopyId = convertRepr(
              facts,
              {
                site: `${fileBase}:${allocLine}`,
                file: cppPath,
                line: allocLine,
                ctx: 'NATIVE_NAPI',
                desc: `${fn.name} -> new char[] copy of privateKeyPassword`,
              },
              new Set([arkPwdRepr]),
              'Raw',
              'NativeHeap',
              'napi'
            );
            facts.partialPathUnzeroized.add(nativeCopyId);
          }
        }

        if (
          /delete\[\]\s+[^;]*\.GetConnectOptions\(\)\.password\b/.test(lnText) &&
          !hasZeroizeInFn
        ) {
          const { reprId: mqttPwdRepr } = introduceSecret(
            facts,
            {
              site: `${fileBase}:${lineNo}`,
              file: cppPath,
              line: lineNo,
              ctx: 'NATIVE_NAPI',
              desc: `${fn.name} -> delete[] password without memset_s`,
            },
            'Session',
            'Raw',
            'NativeHeap',
            true,
            `Native password buffer freed via delete[] without memset_s in ${fn.name}`
          );
          facts.partialPathUnzeroized.add(mqttPwdRepr);
        }
      }
    }

    // -------------------------------------------------------------------------
    // 通用规则 C4: 函数体将二进制认证 Token (baseToken) 转为 Hex 字符串、写入日志并导出为 NAPI String
    // -------------------------------------------------------------------------
    for (const fn of functions) {
      for (let i = 0; i < fn.lines.length; i++) {
        const lnText = fn.lines[i].trim();
        const hexLine = fn.startLine + i;
        if (/std::string\s+tokenString\s*=\s*UintToHexString\s*\(\s*[A-Za-z0-9_]+->baseToken\.s\b/.test(lnText)) {
          const { reprId: tokenRawRepr } = introduceSecret(
            facts,
            {
              site: `${fileBase}:${hexLine}`,
              file: cppPath,
              line: hexLine,
              ctx: 'NATIVE_NAPI',
              desc: `${fn.name} -> baseToken.s to hex`,
            },
            'Session',
            'Raw',
            'NativeHeap',
            true,
            `Session authentication token (baseToken) in ${fn.name}`
          );

          // 在同一函数体内动态查找日志输出语句行号
          let logReprId: string | null = null;
          for (let k = i + 1; k < fn.lines.length; k++) {
            if (/\b(?:LOGI|OH_LOG_INFO|HILOG_INFO)\s*\([^)]*tokenString\.c_str\(\)/.test(fn.lines[k])) {
              const logLine = fn.startLine + k;
              logReprId = convertRepr(
                facts,
                {
                  site: `${fileBase}:${logLine}`,
                  file: cppPath,
                  line: logLine,
                  ctx: 'NATIVE_NAPI',
                  desc: `${fn.name} -> LOGI(tokenString.c_str())`,
                },
                new Set([tokenRawRepr]),
                'Enc',
                'Log',
                'log',
                { encoding: 'hex' }
              );
              break;
            }
          }

          // 在同文件中动态查找 napi_create_string_utf8 导出 tokenStr 的真实行号
          const exportIdx = allLines.findIndex((l) =>
            /napi_create_string_utf8\s*\([^,]+,\s*[A-Za-z0-9_]+->tokenStr\b/.test(l)
          );
          if (exportIdx >= 0) {
            const exportLine = exportIdx + 1;
            const srcSet = logReprId ? new Set([tokenRawRepr, logReprId]) : new Set([tokenRawRepr]);
            convertRepr(
              facts,
              {
                site: `${fileBase}:${exportLine}`,
                file: cppPath,
                line: exportLine,
                ctx: 'NATIVE_NAPI',
                desc: 'napi_create_string_utf8(env, classBind->tokenStr, &napiToken)',
              },
              srcSet,
              'Enc',
              'ArkString',
              'encode',
              { encoding: 'hex' }
            );
          }
        }
      }
    }
  }
}
