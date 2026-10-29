/**
 * eval/run_benchmark_eval.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— HarmonyKeyRepBench 64 样本 × 9 种方法（B0/B1/B2 + 5 项消融 + 完整版）实测评估脚本
 */

import * as fs from 'fs';
import * as path from 'path';
import { generateAllBenchmarks, BenchmarkCaseMeta } from '../bench/generate_benchmark';
import { analyzeProject } from '../core-ts/analysis/repflow';
import { runBaselineB0 } from '../baselines/b0_regex_entropy';
import { runBaselineB1 } from '../baselines/b1_binary_taint';
import { runBaselineB2 } from '../baselines/b2_jscamd_rules';

export interface MethodEvalSummary {
  methodName: string;
  TP: number;
  FP: number;
  TN: number;
  FN: number;
  precision: number;
  recall: number;
  f1: number;
  deltaF1: number;
  groupAFpr: number;
  familyPassPairs: Record<string, string>;
  medianTimeMs: number;
  p95TimeMs: number;
  uncertainRatio: number;
}

interface RunnerDef {
  name: string;
  run: (projectDir: string) => { detected: boolean; uncertainCount: number; totalFindings: number };
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return Number(sorted[idx].toFixed(2));
}

export function runFullBenchmarkEvaluation(): MethodEvalSummary[] {
  const manifestPath = path.resolve(__dirname, '../bench/benchmark_manifest.json');
  let cases: BenchmarkCaseMeta[];
  if (fs.existsSync(manifestPath)) {
    cases = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  } else {
    cases = generateAllBenchmarks();
  }

  const runners: RunnerDef[] = [
    {
      name: 'B0 (Regex + Entropy)',
      run: (dir) => {
        const res = runBaselineB0(dir);
        return { detected: res.length > 0, uncertainCount: 0, totalFindings: res.length };
      },
    },
    {
      name: 'B1 (APAK Binary Taint)',
      run: (dir) => {
        const res = runBaselineB1(dir);
        return { detected: res.length > 0, uncertainCount: 0, totalFindings: res.length };
      },
    },
    {
      name: 'B2 (B1 + JScamd Constraints)',
      run: (dir) => {
        const res = runBaselineB2(dir);
        return { detected: res.length > 0, uncertainCount: 0, totalFindings: res.length };
      },
    },
    {
      name: 'KeyScope-HM (-Identity)',
      run: (dir) => {
        const res = analyzeProject(dir, { disableIdentity: true, enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
    {
      name: 'KeyScope-HM (-CopyAlias)',
      run: (dir) => {
        const res = analyzeProject(dir, { disableCopyAlias: true, enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
    {
      name: 'KeyScope-HM (-Ctx)',
      run: (dir) => {
        const res = analyzeProject(dir, { disableCtx: true, enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
    {
      name: 'KeyScope-HM (-Rec)',
      run: (dir) => {
        const res = analyzeProject(dir, { disableRec: true, enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
    {
      name: 'KeyScope-HM (-Handle)',
      run: (dir) => {
        const res = analyzeProject(dir, { disableHandle: true, enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
    {
      name: 'KeyScope-HM (Full v3)',
      run: (dir) => {
        const res = analyzeProject(dir, { enableExtensions: true });
        const unc = res.findings.filter((f) => f.grade === 'Uncertain').length;
        return { detected: res.findings.length > 0, uncertainCount: unc, totalFindings: res.findings.length };
      },
    },
  ];

  const summaries: MethodEvalSummary[] = [];
  const families = ['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8'];

  for (const runner of runners) {
    let TP = 0;
    let FP = 0;
    let TN = 0;
    let FN = 0;
    let totalUncertain = 0;
    let totalFindingsAll = 0;
    const times: number[] = [];
    const casePassed = new Map<string, boolean>();

    for (const c of cases) {
      const t0 = performance.now();
      const out = runner.run(c.projectDir);
      const dt = performance.now() - t0;
      times.push(dt);

      totalUncertain += out.uncertainCount;
      totalFindingsAll += out.totalFindings;

      if (c.expectedVulnerable) {
        if (out.detected) {
          TP++;
          casePassed.set(c.id, true);
        } else {
          FN++;
          casePassed.set(c.id, false);
        }
      } else {
        if (out.detected) {
          FP++;
          casePassed.set(c.id, false);
        } else {
          TN++;
          casePassed.set(c.id, true);
        }
      }
    }

    // 统计每组 F1..F8 成对通过数（只有同一变体的 A_Safe 与 B_Risky 均判断正确才算该对通过）
    const familyPassPairs: Record<string, string> = {};
    for (const fam of families) {
      const famCasesA = cases.filter((c) => c.family === fam && c.pairRole === 'A_Safe');
      let passedPairs = 0;
      for (const ca of famCasesA) {
        const cbId = ca.id.replace('_A_Safe', '_B_Risky');
        if (casePassed.get(ca.id) && casePassed.get(cbId)) {
          passedPairs++;
        }
      }
      familyPassPairs[fam] = `${passedPairs}/${famCasesA.length}`;
    }

    const precision = TP + FP > 0 ? Number(((TP / (TP + FP)) * 100).toFixed(2)) : 0;
    const recall = TP + FN > 0 ? Number(((TP / (TP + FN)) * 100).toFixed(2)) : 0;
    const f1 =
      precision + recall > 0
        ? Number((((2 * precision * recall) / (precision + recall))).toFixed(2))
        : 0;
    const groupAFpr = FP + TN > 0 ? Number(((FP / (FP + TN)) * 100).toFixed(2)) : 0;
    times.sort((a, b) => a - b);

    summaries.push({
      methodName: runner.name,
      TP,
      FP,
      TN,
      FN,
      precision,
      recall,
      f1,
      deltaF1: 0,
      groupAFpr,
      familyPassPairs,
      medianTimeMs: percentile(times, 0.5),
      p95TimeMs: percentile(times, 0.95),
      uncertainRatio:
        totalFindingsAll > 0 ? Number(((totalUncertain / totalFindingsAll) * 100).toFixed(2)) : 0,
    });
  }

  const fullF1 = summaries[summaries.length - 1].f1;
  for (const s of summaries) {
    s.deltaF1 = Number((s.f1 - fullF1).toFixed(2));
  }

  const outPath = path.resolve(__dirname, 'benchmark_results.json');
  fs.writeFileSync(outPath, JSON.stringify(summaries, null, 2), 'utf-8');

  console.log('\n================ HarmonyKeyRepBench (64 Samples) Evaluation Results ================');
  console.table(
    summaries.map((s) => ({
      Method: s.methodName,
      TP: s.TP,
      FP: s.FP,
      TN: s.TN,
      FN: s.FN,
      'P (%)': s.precision,
      'R (%)': s.recall,
      'F1 (%)': s.f1,
      'ΔF1': s.deltaF1,
      'A-FPR (%)': s.groupAFpr,
      F1: s.familyPassPairs.F1,
      F2: s.familyPassPairs.F2,
      F3: s.familyPassPairs.F3,
      F4: s.familyPassPairs.F4,
      F5: s.familyPassPairs.F5,
      F6: s.familyPassPairs.F6,
      F7: s.familyPassPairs.F7,
      F8: s.familyPassPairs.F8,
      'Med(ms)': s.medianTimeMs,
    }))
  );

  return summaries;
}

if (require.main === module) {
  runFullBenchmarkEvaluation();
}
