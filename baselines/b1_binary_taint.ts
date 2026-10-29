/**
 * baselines/b1_binary_taint.ts
 * 基线 B1 (对应 v3 7.2 节 B1)：同底座 (ArkAnalyzer) 二元污点分析
 *
 * 与完整版 KeyScope-HM 共享相同的 ArkAnalyzer 前端与跨语言桥接底座，但：
 * 1. 仅使用单一布尔污点标签 (Tainted = true)，不区分 Handle(句柄)、OneWay(单向摘要) 与 KeyMaterial；
 * 2. 将 wrapKey 视作净化器 (Sanitizer)，否则所有加密存储都会误报；因此无法通过 Rec 不动点检出同域明文 KEK (F3-B)；
 * 3. 不区分逻辑秘密身份 (κ) 的差异化策略，也不跟踪 NAPI 拷贝/别名内存清零 (F8)。
 */

import { analyzeProject } from '../core-ts/analysis/repflow';
import { BaselineFinding } from './b0_regex_entropy';

export function runBaselineB1(projectDir: string): BaselineFinding[] {
  // 在同底座上开启退化为二元污点的配置：
  // - disableHandle: true (别名也被标为污点源)
  // - disableIdentity: true (单一污点标签)
  // - disableRec: true (wrap 视为直接净化，不做 KEK 同域可恢复不动点)
  // - disableCtx: true (不做 1-call-site 辅助函数克隆)
  // - enableExtensions: false (二元污点仅做 source -> sink 连通，不做 Must-Zeroization 拷贝/别名区分)
  const res = analyzeProject(projectDir, {
    disableHandle: true,
    disableIdentity: true,
    disableRec: true,
    disableCtx: true,
    disableCopyAlias: true,
    enableExtensions: false,
  });

  const findings: BaselineFinding[] = res.findings.map((f) => ({
    rule: `B1_Taint_${f.rule}`,
    file: f.file,
    line: f.line,
    reason: f.reason,
  }));

  // 此外，二元污点不区分 OneWay (digestSync) 与可逆编码，只要输入被污染且 digest 结果流入 Storage/Log 也会报警
  for (const r of res.facts.reprs.values()) {
    if (r.form === 'OneWay') {
      // 检查是否有从该 OneWay 派生的 Storage 或 Log 表示
      for (const edge of res.facts.prov) {
        if (edge.from === r.id) {
          const dst = res.facts.reprs.get(edge.to);
          if (dst && (dst.container === 'Storage' || dst.container === 'Log' || dst.container === 'IPC')) {
            findings.push({
              rule: 'B1_Taint_OneWaySink',
              file: dst.file,
              line: dst.line,
              reason: `二元污点分析未区分单向摘要 (OneWay) 与可逆编码，将 ${r.id} 的输出视作受污染秘密`,
            });
          }
        }
      }
    }
  }

  return findings;
}
