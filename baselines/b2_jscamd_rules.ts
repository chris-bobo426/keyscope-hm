/**
 * baselines/b2_jscamd_rules.ts
 * 基线 B2 (对应 v3 7.2 节 B2)：B1 同底座污点 + JScamd (USENIX Security 2026) 风格密码 API 安全约束规则
 *
 * 相比 B1 的增强：
 * 1. 引入密码 API 语义约束（识别 huks.generateKeyItem 参数为别名句柄、识别 md.digestSync 为单向杂凑），消除 F1 和 F6 的误报；
 * 2. 支持上下文敏感的数据流追踪；
 * 局限性（无需任何硬编码过滤，完全由模型机制决定）：
 * 1. 不具备可恢复性不动点 Rec(κ, D) (disableRec: true)，将 wrapKey 视作满足约束的加密操作而无法推理同域共存 KEK (F3-B 漏报)；
 * 2. 不具备按逻辑秘密身份 κ 区分的生命周期策略 (disableIdentity: true)，多秘密汇合时丢失 Session 与 LongTerm 的身份区分 (F4-B 漏报)；
 * 3. 不具备跨语言 NAPI 拷贝 vs 别名内存共享与清零模型 (enableExtensions: false)，无法检出 F8-B。
 */

import { analyzeProject } from '../core-ts/analysis/repflow';
import { BaselineFinding } from './b0_regex_entropy';

export function runBaselineB2(projectDir: string): BaselineFinding[] {
  const res = analyzeProject(projectDir, {
    disableHandle: false,
    disableIdentity: true,
    disableRec: true,
    disableCtx: false,
    disableCopyAlias: true,
    enableExtensions: false,
  });

  return res.findings.map((f) => ({
    rule: `B2_JScamd_${f.rule}`,
    file: f.file,
    line: f.line,
    reason: f.reason,
  }));
}
