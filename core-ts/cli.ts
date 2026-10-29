/**
 * core-ts/cli.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 命令行分析入口
 *
 * 用法：
 *   npx tsx core-ts/cli.ts <projectDir> [--output-dir <dir>] [--all-realworld]
 */

import * as fs from 'fs';
import * as path from 'path';
import { analyzeProject, AnalysisResult } from './analysis/repflow';
import { generateAllReports } from '../report/report_generator';

function printHelp(): void {
  console.log(`
鸿钥卫士 KeyScope-HM v3.0 — 面向 HarmonyOS 混合应用的跨运行时密钥表示与暴露风险分析系统

用法:
  npx tsx core-ts/cli.ts <projectDir> [--output-dir <outDir>]
  npx tsx core-ts/cli.ts --all-realworld [--output-dir <outDir>]

示例:
  npx tsx core-ts/cli.ts bench/samples/F3_v1_B_Risky --output-dir report/output
  npx tsx core-ts/cli.ts --all-realworld --output-dir report/output
`);
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  let outputDir = path.resolve(__dirname, '../report/output');
  const outIdx = args.indexOf('--output-dir');
  if (outIdx >= 0 && args[outIdx + 1]) {
    outputDir = path.resolve(args[outIdx + 1]);
  }

  const scanAllRealworld =
    args.includes('--all-realworld') || args.filter((a) => !a.startsWith('--')).length === 0;

  const results: AnalysisResult[] = [];

  if (scanAllRealworld) {
    const reposRoot = path.resolve(__dirname, '../realworld/repos');
    const entries = fs.readdirSync(reposRoot, { withFileTypes: true }).filter((e) => e.isDirectory());
    console.log(`[KeyScope-HM CLI] 扫描 realworld/repos 下全部 ${entries.length} 个真实开源鸿蒙工程...`);
    for (const entry of entries) {
      const repoDir = path.join(reposRoot, entry.name);
      const res = analyzeProject(repoDir);
      results.push(res);
      console.log(
        `  ✔ ${entry.name.padEnd(38)} | κ=${res.facts.secrets.size}, ρ=${res.facts.reprs.size}, Findings=${res.findings.length}, CBOM=${res.cbomAssets.length} (${res.durationMs.toFixed(1)} ms)`
      );
    }
  } else {
    const targetDir = path.resolve(args[0]);
    if (!fs.existsSync(targetDir)) {
      console.error(`[Error] 目标工程目录不存在: ${targetDir}`);
      process.exit(1);
    }
    console.log(`[KeyScope-HM CLI] 正在分析工程: ${targetDir}`);
    const res = analyzeProject(targetDir);
    results.push(res);
    console.log(
      `  ✔ ${res.projectName} | ArkTS=${res.arkFilesCount}, C++=${res.cppFilesCount} | κ=${res.facts.secrets.size}, ρ=${res.facts.reprs.size}, Findings=${res.findings.length}, CBOM=${res.cbomAssets.length} (${res.durationMs.toFixed(1)} ms)`
    );
    for (const f of res.findings) {
      console.log(`    - [${f.grade}] [${f.rule}] (${f.cwe}) @ ${f.site}: ${f.reason}`);
    }
  }

  const paths = generateAllReports(results, outputDir);
  console.log('\n[KeyScope-HM CLI] 多模态分析报告已生成:');
  console.log(`  - HTML 溯源图报告 : ${paths.htmlPath}`);
  console.log(`  - SARIF 2.1.0 报告: ${paths.sarifPath}`);
  console.log(`  - CycloneDX CBOM  : ${paths.cbomPath}`);
}

if (require.main === module) {
  main();
}
