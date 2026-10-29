/**
 * core-ts/grade.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 表示溯源链重建、纯度置信度分级与扩展规则 (E1/E2/E3) 判定
 */

import {
  Facts,
  ConfidenceGrade,
  ProvenanceEdge,
} from './repr';
import { PolicyViolation } from './rec';

export interface GradedFinding {
  id: string;
  rule: 'V1' | 'V2' | 'V3' | 'E1_M4' | 'E2_M3' | 'E3_M2';
  cwe: string;
  grade: ConfidenceGrade;
  secretId: string;
  secretClass: string;
  reprId: string;
  form: string;
  container: string;
  domain: string;
  file: string;
  line: number;
  site: string;
  reason: string;
  provenancePath: ProvenanceEdge[];
  remediation: string;
}

/**
 * 在表示溯源图 Prov 中用反向 BFS 重建从承载 κ 的源表示到目标表示 targetReprId 的溯源路径 π
 */
export function buildProvenancePath(
  f: Facts,
  secretId: string,
  targetReprId: string
): ProvenanceEdge[] {
  const incoming = new Map<string, ProvenanceEdge[]>();
  for (const edge of f.prov) {
    if (edge.from === edge.to && edge.op === 'alias') continue;
    const list = incoming.get(edge.to) ?? [];
    list.push(edge);
    incoming.set(edge.to, list);
  }

  const visited = new Set<string>([targetReprId]);
  const parentEdge = new Map<string, ProvenanceEdge>();
  const queue: string[] = [targetReprId];
  let rootRepr = targetReprId;

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const inEdges = incoming.get(curr) ?? [];
    let advanced = false;
    for (const e of inEdges) {
      const fromCarries = f.getCarries(e.from);
      const fromHandles = f.getHandle(e.from);
      if (fromCarries.has(secretId) || fromHandles.has(secretId) || e.op === 'wrap') {
        if (!visited.has(e.from)) {
          visited.add(e.from);
          parentEdge.set(e.from, e);
          queue.push(e.from);
          rootRepr = e.from;
          advanced = true;
        }
      }
    }
    if (!advanced && inEdges.length === 0) {
      rootRepr = curr;
    }
  }

  // 正向还原路径
  const path: ProvenanceEdge[] = [];
  let cursor = rootRepr;
  const guard = new Set<string>();
  while (cursor !== targetReprId && !guard.has(cursor)) {
    guard.add(cursor);
    const e = parentEdge.get(cursor);
    if (!e) break;
    path.push(e);
    cursor = e.to;
  }

  // 附加上 targetReprId 上的 alias 边（如有）
  for (const edge of f.prov) {
    if (edge.op === 'alias' && (edge.from === rootRepr || edge.to === targetReprId)) {
      path.push(edge);
    }
  }

  return path;
}

/**
 * 置信度分级算法（对应 v3 文档 5.5 节）：
 * - Uncertain: 路径经过未知 Native 摘要、反射或反编译缺口
 * - Medium: LongTerm 密钥触发 V1 (D_mem)；或路径上存在多秘密汇合 (|carries(ρ)| > 1)；或依赖启发式类别推断
 * - High: 路径上指向纯度为单元素集合、无未知摘要、类别无歧义
 */
export function gradeViolations(
  f: Facts,
  violations: PolicyViolation[]
): GradedFinding[] {
  const findings: GradedFinding[] = [];
  let idx = 1;

  for (const v of violations) {
    const path = buildProvenancePath(f, v.secret.id, v.repr.id);
    let grade: ConfidenceGrade = 'High';

    const anyUncertain =
      v.repr.uncertain ||
      path.some((e) => f.reprs.get(e.from)?.uncertain || f.reprs.get(e.to)?.uncertain);

    if (anyUncertain) {
      grade = 'Uncertain';
    } else {
      const multiSecretMixed = (f.getCarries(v.repr.id).size > 1);
      const isLongTermV1 = v.secret.cls === 'LongTerm' && v.rule === 'V1';
      if (multiSecretMixed || isLongTermV1 || (!v.secret.clsFromUser && !v.secret.unambiguousIntro)) {
        grade = 'Medium';
      }
    }

    let remediation = '';
    if (v.rule === 'V1') {
      remediation =
        '避免使用 Base64Helper.encodeToString / TextDecoder / napi_create_string_utf8 将密钥材料转换为不可变 ArkTS String；改用 Uint8Array / ArrayBuffer 承载并在使用完毕后调用 .fill(0) 及 memset_s 清零。';
    } else if (v.rule === 'V2') {
      remediation =
        v.viaWrappedKek
          ? '禁止将明文包装密钥 (KEK) 与被包装密文存储在同一持久化介质中；应使用 HUKS 硬件绑定密钥 (huks.generateKeyItem) 对密钥材料进行加密信封包装后再持久化。'
          : '会话密钥 (Session/Ephemeral) 严禁写入 Preferences/数据库或通过明文 Want 发送；长期密钥落盘前必须使用 HUKS 密钥包装，或仅存储 HUKS 密钥别名 (KeyHandle)。';
    } else {
      remediation = '立即移除将密钥材料或其可逆编码传入 hilog / console 的日志语句。';
    }

    findings.push({
      id: `KS-${String(idx++).padStart(3, '0')}`,
      rule: v.rule,
      cwe: v.cwe,
      grade,
      secretId: v.secret.id,
      secretClass: v.secret.cls,
      reprId: v.repr.id,
      form: v.repr.form + (v.repr.encoding ? `<${v.repr.encoding}>` : ''),
      container: v.repr.container,
      domain: v.domain,
      file: v.repr.file,
      line: v.repr.line,
      site: v.repr.site,
      reason: v.reason,
      provenancePath: path,
      remediation,
    });
  }

  // 若启用了扩展模块 E1 (M4 清零)、E2 (M3 Nonce 复用)、E3 (M2 导入前暴露)
  if (f.options.enableExtensions !== false) {
    // E1 (M4): 检查 NativeHeap 与 ArkBuffer 中的原始密钥材料表示是否所有路径均已安全清零
    for (const r of f.reprs.values()) {
      if (r.form === 'Raw' && (r.container === 'NativeHeap' || r.container === 'ArkBuffer')) {
        const ks = f.getCarries(r.id);
        if (ks.size === 0) continue;
        const firstSecretId = [...ks][0];
        const sec = f.secrets.get(firstSecretId);
        if (!sec || sec.cls === 'HardwareBound') continue;

        if (f.plainMemset.has(r.id)) {
          findings.push({
            id: `KS-${String(idx++).padStart(3, '0')}`,
            rule: 'E1_M4',
            cwe: 'CWE-14/CWE-226',
            grade: 'High',
            secretId: firstSecretId,
            secretClass: sec.cls,
            reprId: r.id,
            form: r.form,
            container: r.container,
            domain: 'D_mem',
            file: r.file,
            line: r.line,
            site: r.site,
            reason: `缓冲区表示 ${r.id} 使用了普通 memset 清零，在编译器 -O2 死存储消除 (DSE) 优化下清零指令会被移除`,
            provenancePath: buildProvenancePath(f, firstSecretId, r.id),
            remediation: '将普通 memset 替换为防编译器优化的 memset_s、explicit_bzero 或 OPENSSL_cleanse。',
          });
        } else if (f.partialPathUnzeroized.has(r.id) || (!f.zeroizedMust.has(r.id) && r.container === 'NativeHeap')) {
          findings.push({
            id: `KS-${String(idx++).padStart(3, '0')}`,
            rule: 'E1_M4',
            cwe: 'CWE-226',
            grade: f.partialPathUnzeroized.has(r.id) ? 'High' : 'Medium',
            secretId: firstSecretId,
            secretClass: sec.cls,
            reprId: r.id,
            form: r.form,
            container: r.container,
            domain: 'D_mem',
            file: r.file,
            line: r.line,
            site: r.site,
            reason: f.partialPathUnzeroized.has(r.id)
              ? `缓冲区表示 ${r.id} 在异常或提前返回分支上遗漏了清零操作，违反 Must-Zeroization 要求`
              : `Native 密钥缓冲区表示 ${r.id} 在跨边界拷贝后未对原件执行安全清零（仅清零副本不等于清零原件）`,
            provenancePath: buildProvenancePath(f, firstSecretId, r.id),
            remediation:
              '确保所有退出分支（含错误返回分支）及跨语言拷贝的原件与副本均调用 memset_s / explicit_bzero / .fill(0) 清零。',
          });
        }
      }
    }

    // E2 (M3): 检查 GCM/CTR Nonce 复用与静态 IV
    for (const nr of f.nonceRecords) {
      if (nr.ivIsStaticOrReused) {
        findings.push({
          id: `KS-${String(idx++).padStart(3, '0')}`,
          rule: 'E2_M3',
          cwe: 'CWE-323/CWE-329',
          grade: 'High',
          secretId: nr.keyReprIds[0] ?? 'κ_cipher',
          secretClass: 'Session',
          reprId: nr.ivSource,
          form: 'Raw',
          container: 'ArkBuffer',
          domain: 'D_safe',
          file: nr.file,
          line: nr.line,
          site: nr.site,
          reason: `在 ${nr.mode} 模式下检测到静态或跨次复用的 IV/Nonce (${nr.ivSource})，直接破坏认证加密机密性与完整性`,
          provenancePath: [],
          remediation: '每次调用 cipher.init 加密时均应使用 cryptoFramework.createRandom().generateRandomSync(12) 生成全新随机 Nonce。',
        });
      }
    }

    // E3 (M2): 检查 huks.importKeyItem 导入前的暴露链
    for (const imp of f.huksImports) {
      for (const reprId of imp.inDataReprs) {
        const ks = f.getCarries(reprId);
        for (const kId of ks) {
          const path = buildProvenancePath(f, kId, reprId);
          // 检查该秘密在程序中是否存在 ArkString 或 Log 表示
          let hasPreExposure = false;
          for (const r of f.reprs.values()) {
            if (f.getCarries(r.id).has(kId) && (r.container === 'ArkString' || r.container === 'Log')) {
              hasPreExposure = true;
              break;
            }
          }
          if (hasPreExposure || path.length >= 2) {
            findings.push({
              id: `KS-${String(idx++).padStart(3, '0')}`,
              rule: 'E3_M2',
              cwe: 'CWE-312/CWE-532',
              grade: 'Medium',
              secretId: kId,
              secretClass: 'LongTerm',
              reprId,
              form: 'Raw',
              container: 'HUKS',
              domain: 'D_mem',
              file: imp.file,
              line: imp.line,
              site: imp.site,
              reason: `明文密钥 ${kId} 在调用 huks.importKeyItem('${imp.aliasName}') 导入前经历了明文暴露或多层非受控复制`,
              provenancePath: path,
              remediation: '优先使用 huks.generateKeyItem 在硬件内部生成密钥，或使用 huks.importWrappedKeyItem 加密包装导入。',
            });
          }
        }
      }
    }
  }

  return findings;
}
