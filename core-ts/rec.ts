/**
 * core-ts/rec.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 可恢复性最小不动点 Rec(κ, D) 与生命周期策略违规判定
 *
 * 形式化定义：
 * Rule 1 (直接可恢复):
 *   Rec(κ, D) <= ∃ρ: κ ∈ carries(ρ) ∧ dom(ρ) = D ∧ form(ρ) ∈ {Raw, Enc, KeyObj}
 * Rule 2 (包装递归可恢复，可分层 Datalog 正递归):
 *   Rec(κ, D) <= ∃ρ: κ ∈ carries(ρ) ∧ dom(ρ) = D ∧ form(ρ) = Wrapped
 *                ∧ ∃κ' ∈ wrapBy(ρ): Rec(κ', D) ∧ cls(κ') != HardwareBound
 */

import {
  Facts,
  Domain,
  domOf,
  SecretClass,
  Repr,
  Secret,
} from './repr';

const DIRECT_RECOVERABLE_FORMS = new Set<string>(['Raw', 'Enc', 'KeyObj']);

export interface RecoverableWitness {
  secretId: string;
  domain: Domain;
  reprId: string;
  viaWrappedKek?: string;
}

export interface PolicyViolation {
  secret: Secret;
  repr: Repr;
  domain: Domain;
  rule: 'V1' | 'V2' | 'V3';
  cwe: string;
  viaWrappedKek?: string;
  reason: string;
}

/**
 * 求解最小不动点 Rec(κ, D)，返回 Map<`${secretId}|${Domain}`, RecoverableWitness>
 * 单调性保证：只含正递归，有限事实空间 H × D 上有限步必然收敛
 */
export function computeRec(f: Facts): Map<string, RecoverableWitness> {
  const rec = new Map<string, RecoverableWitness>();
  let changed = true;

  while (changed) {
    changed = false;
    for (const r of f.reprs.values()) {
      const D = domOf(r.container);
      if (D === 'D_safe') continue;

      const carriedSecrets = f.getCarries(r.id);
      if (carriedSecrets.size === 0) continue;

      const directSet = f.getDirectCarries(r.id);
      const keks = f.getWrapBy(r.id);

      for (const kId of carriedSecrets) {
        const sec = f.secrets.get(kId);
        // HardwareBound 秘密除非在 -Handle 消融下被误标为 carries，否则在应用层不可恢复
        if (sec?.cls === 'HardwareBound' && !f.options.disableHandle) {
          continue;
        }

        // Rule 1: 该秘密 kId 以未包装形式直接到达 r，或 r 为无包装记录的可恢复形式
        let isRecoverable =
          DIRECT_RECOVERABLE_FORMS.has(r.form) &&
          (directSet.has(kId) || (directSet.size === 0 && keks.size === 0));
        let unwrappedByKek: string | undefined;

        // Rule 2: 包装密钥递归可恢复判定（若未开启 -Rec 消融）
        if (!isRecoverable && (r.form === 'Wrapped' || keks.size > 0) && !f.options.disableRec) {
          for (const kekId of keks) {
            const kekSecret = f.secrets.get(kekId);
            if (kekSecret?.cls === 'HardwareBound') continue;
            if (rec.has(`${kekId}|${D}`)) {
              isRecoverable = true;
              unwrappedByKek = kekId;
              break;
            }
          }
        }

        if (!isRecoverable) continue;

        const key = `${kId}|${D}|${r.id}`;
        const summaryKey = `${kId}|${D}`;
        if (!rec.has(key)) {
          const witness: RecoverableWitness = {
            secretId: kId,
            domain: D,
            reprId: r.id,
            viaWrappedKek: unwrappedByKek,
          };
          rec.set(key, witness);
          if (!rec.has(summaryKey)) {
            rec.set(summaryKey, witness);
          }
          changed = true;
        }
      }
    }
  }

  return rec;
}

const FORBIDDEN_DOMAINS: Record<SecretClass, Domain[]> = {
  Session: ['D_mem', 'D_store', 'D_ipc', 'D_log'],
  LongTerm: ['D_mem', 'D_ipc', 'D_log'], // LongTerm 持久密钥在策略允许下可驻留 D_store，但若作为明文 KEK 与被包装 Session 密钥共存于 D_store，会通过 Rec 不动点推导使 Session 密钥在 D_store 可恢复而触发 V2
  HardwareBound: ['D_mem', 'D_store', 'D_ipc', 'D_log'],
};

const DOMAIN_TO_RULE: Record<Exclude<Domain, 'D_safe'>, { rule: 'V1' | 'V2' | 'V3'; cwe: string }> = {
  D_mem: { rule: 'V1', cwe: 'CWE-316/CWE-226' },
  D_store: { rule: 'V2', cwe: 'CWE-312' },
  D_ipc: { rule: 'V2', cwe: 'CWE-927' },
  D_log: { rule: 'V3', cwe: 'CWE-532' },
};

/**
 * 基于 Rec 不动点结果与每个秘密 κ 的生命周期策略 cls(κ) 判定违规
 */
export function checkPolicyViolations(
  f: Facts,
  rec: Map<string, RecoverableWitness>
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];

  for (const [key, witness] of rec.entries()) {
    // 只遍历带具体 reprId 的条目 `${kId}|${D}|${reprId}`
    const parts = key.split('|');
    if (parts.length < 3) continue;

    const secret = f.secrets.get(witness.secretId);
    const repr = f.reprs.get(witness.reprId);
    if (!secret || !repr || witness.domain === 'D_safe') continue;

    const forbidden = FORBIDDEN_DOMAINS[secret.cls];
    if (!forbidden.includes(witness.domain)) continue;

    const { rule, cwe } = DOMAIN_TO_RULE[witness.domain];
    let reason = '';
    if (rule === 'V1') {
      reason = `逻辑秘密 ${secret.id} (${secret.cls}) 的可恢复表示 ${repr.id} [form=${repr.form}${
        repr.encoding ? `<${repr.encoding}>` : ''
      }] 进入不可按需清零的托管字符串容器 (ArkString / D_mem)，扩大了潜在明文驻留范围`;
    } else if (rule === 'V2') {
      if (witness.viaWrappedKek) {
        reason = `逻辑秘密 ${secret.id} (${secret.cls}) 虽经包装 (${repr.id})，但其包装密钥 ${witness.viaWrappedKek} 在同一攻击域 (${witness.domain}) 中以可恢复明文形式共存，导致不动点 Rec(${secret.id}, ${witness.domain}) 成立`;
      } else {
        reason = `逻辑秘密 ${secret.id} (${secret.cls}) 以可恢复形式 [form=${repr.form}] 越过策略允许的 ${
          witness.domain === 'D_store' ? '持久化存储 (Storage)' : '跨进程传输 (IPC)'
        } 边界`;
      }
    } else {
      reason = `逻辑秘密 ${secret.id} (${secret.cls}) 的可恢复表示 ${repr.id} 被输出至日志域 (D_log)`;
    }

    violations.push({
      secret,
      repr,
      domain: witness.domain,
      rule,
      cwe,
      viaWrappedKek: witness.viaWrappedKek,
      reason,
    });
  }

  return violations;
}
