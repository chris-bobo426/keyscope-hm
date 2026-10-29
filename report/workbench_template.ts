/**
 * report/workbench_template.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 全中文、可视化、白话文解读与编译器底层对照交互式前端工作台
 */

import * as fs from 'fs';
import * as path from 'path';
import { AnalysisResult, analyzeProject } from '../core-ts/analysis/repflow';
import {
  PROJECT_HUMAN_META,
  RULE_HUMAN_MAP,
  CONTAINER_ZH_MAP,
  FORM_ZH_MAP,
  SECRET_CLASS_ZH_MAP,
  OP_ZH_MAP,
} from './human_explanations';

export interface EmbeddedProjectBundle {
  projectName: string;
  titleZh: string;
  subtitleZh: string;
  scenarioDescZh: string;
  group: 'realworld' | 'scenario_pair';
  familyCode?: string;
  isSafeSample?: boolean;
  arkFilesCount: number;
  cppFilesCount: number;
  methodsAnalyzed: number;
  durationMs: number;
  apakStats: AnalysisResult['apakStats'];
  sourceFiles: Array<{ relPath: string; lang: 'ets' | 'cpp'; content: string }>;
  irDump: AnalysisResult['irDump'];
  napiDetails: AnalysisResult['napiDetails'];
  secrets: Array<{ id: string; cls: string; site: string; originDesc?: string }>;
  reprs: Array<{
    id: string;
    container: string;
    form: string;
    encoding: string;
    site: string;
    carries: string[];
    directCarries: string[];
    wrapBy: string[];
    handles: string[];
    mustZeroized: boolean;
  }>;
  prov: AnalysisResult['facts']['prov'];
  findings: AnalysisResult['findings'];
}

function readProjectSources(projectDir: string): Array<{ relPath: string; lang: 'ets' | 'cpp'; content: string }> {
  const out: Array<{ relPath: string; lang: 'ets' | 'cpp'; content: string }> = [];
  const walk = (d: string) => {
    if (!fs.existsSync(d)) return;
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        if (!['node_modules', '.git', 'oh_modules', 'paho.mqtt.c', 'libcoap-4', 'third_party', 'test', 'unittest'].includes(entry.name)) {
          walk(full);
        }
      } else if (entry.isFile()) {
        if (entry.name.endsWith('.ets') || entry.name.endsWith('.ts')) {
          out.push({
            relPath: path.relative(projectDir, full).replace(/\\/g, '/'),
            lang: 'ets',
            content: fs.readFileSync(full, 'utf-8').slice(0, 18000),
          });
        } else if (entry.name.endsWith('.cpp') || entry.name.endsWith('.c')) {
          out.push({
            relPath: path.relative(projectDir, full).replace(/\\/g, '/'),
            lang: 'cpp',
            content: fs.readFileSync(full, 'utf-8').slice(0, 18000),
          });
        }
      }
    }
  };
  walk(projectDir);
  return out.slice(0, 8);
}

export function bundleAnalysisResult(res: AnalysisResult): EmbeddedProjectBundle {
  const meta = PROJECT_HUMAN_META[res.projectName] ?? {
    titleZh: res.projectName,
    subtitleZh: res.findings.length > 0 ? `检出 ${res.findings.length} 处密钥安全风险` : '安全通过密钥体检',
    scenarioDescZh: '自定义或扩展鸿蒙应用工程静态密码安全分析结果。',
    group: 'realworld' as const,
  };

  // 确保包含告警所在源码文件（针对大型 C++ 仓库如 security_huks / security_crypto_framework）
  const sources = readProjectSources(res.projectDir);
  for (const f of res.findings) {
    if (f.file && fs.existsSync(f.file)) {
      const rel = path.relative(res.projectDir, f.file).replace(/\\/g, '/');
      if (!sources.some((s) => s.relPath === rel)) {
        sources.unshift({
          relPath: rel,
          lang: f.file.endsWith('.cpp') || f.file.endsWith('.c') ? 'cpp' : 'ets',
          content: fs.readFileSync(f.file, 'utf-8').slice(0, 22000),
        });
      }
    }
  }

  return {
    projectName: res.projectName,
    titleZh: meta.titleZh,
    subtitleZh: meta.subtitleZh,
    scenarioDescZh: meta.scenarioDescZh,
    group: meta.group,
    familyCode: meta.familyCode,
    isSafeSample: meta.isSafeSample,
    arkFilesCount: res.arkFilesCount,
    cppFilesCount: res.cppFilesCount,
    methodsAnalyzed: res.methodsAnalyzed,
    durationMs: Number(res.durationMs.toFixed(2)),
    apakStats: res.apakStats,
    sourceFiles: sources.slice(0, 8),
    irDump: res.irDump.slice(0, 30),
    napiDetails: res.napiDetails.slice(0, 20),
    secrets: Array.from(res.facts.secrets.values()),
    reprs: Array.from(res.facts.reprs.values())
      .filter((r) => {
        const c = res.facts.getCarries(r.id);
        const h = res.facts.getHandle(r.id);
        return c.size > 0 || h.size > 0 || res.findings.some((f) => f.reprId === r.id);
      })
      .map((r) => ({
        id: r.id,
        container: r.container,
        form: r.form,
        encoding: r.encoding ?? 'none',
        site: r.site,
        carries: Array.from(res.facts.getCarries(r.id)),
        directCarries: Array.from(res.facts.getDirectCarries(r.id)),
        wrapBy: Array.from(res.facts.getWrapBy(r.id)),
        handles: Array.from(res.facts.getHandle(r.id)),
        mustZeroized: res.facts.zeroizedMust.has(r.id),
      })),
    prov: res.facts.prov,
    findings: res.findings,
  };
}

export function collectShowcaseBundles(results: AnalysisResult[]): EmbeddedProjectBundle[] {
  const rootDir = path.resolve(__dirname, '..');
  const bundles: EmbeddedProjectBundle[] = [];
  const seen = new Set<string>();

  // 1. 先放入 8 个真实开源鸿蒙项目（按最具代表性排序）
  const preferredOrder = [
    'openharmony_security_crypto_framework',
    'openharmony_security_huks',
    'ohos_mqtt',
    'ohos_coap',
    'harmonyos_crypto_collection',
    'ohos_crypto_js',
    'harmonyos_cipher',
    'harmonyos_preferences',
  ];
  const resMap = new Map(results.map((r) => [r.projectName, r]));
  for (const name of preferredOrder) {
    const r = resMap.get(name);
    if (r) {
      bundles.push(bundleAnalysisResult(r));
      seen.add(name);
    }
  }
  for (const r of results) {
    if (!seen.has(r.projectName)) {
      bundles.push(bundleAnalysisResult(r));
      seen.add(r.projectName);
    }
  }

  // 2. 放入 F1 - F8 八大核心场景的“安全示范 vs 危险反例”配对样本（共 16 个典型工程）
  const benchSamples = [
    'F1_v1_direct_A_Safe',
    'F1_v1_direct_B_Risky',
    'F2_v1_direct_A_Safe',
    'F2_v1_direct_B_Risky',
    'F3_v1_direct_A_Safe',
    'F3_v1_direct_B_Risky',
    'F4_v1_direct_A_Safe',
    'F4_v1_direct_B_Risky',
    'F5_v1_direct_A_Safe',
    'F5_v1_direct_B_Risky',
    'F6_v1_direct_A_Safe',
    'F6_v1_direct_B_Risky',
    'F7_v1_direct_A_Safe',
    'F7_v1_direct_B_Risky',
    'F8_v1_direct_A_Safe',
    'F8_v1_direct_B_Risky',
  ];

  for (const sName of benchSamples) {
    if (seen.has(sName)) continue;
    const dir = path.join(rootDir, 'bench', 'samples', sName);
    if (fs.existsSync(dir)) {
      const r = analyzeProject(dir);
      bundles.push(bundleAnalysisResult(r));
      seen.add(r.projectName);
    }
  }

  return bundles;
}

export function renderInteractiveWorkbenchHtml(
  results: AnalysisResult[],
  allFindings: Array<{ project: string; finding: AnalysisResult['findings'][number] }>,
  allCbom: Array<{ project: string; asset: AnalysisResult['cbomAssets'][number] }>
): string {
  const rootDir = path.resolve(__dirname, '..');
  const benchPath = path.join(rootDir, 'eval', 'benchmark_results.json');
  const rwPath = path.join(rootDir, 'realworld', 'realworld_summary.json');
  const disasmPath = path.join(rootDir, 'dynamic', 'disasm_experiment', 'disasm_results.json');
  const heapPath = path.join(rootDir, 'dynamic', 'heap_experiment', 'heap_results.json');

  const benchData = fs.existsSync(benchPath) ? JSON.parse(fs.readFileSync(benchPath, 'utf-8')) : [];
  const rwData = fs.existsSync(rwPath) ? JSON.parse(fs.readFileSync(rwPath, 'utf-8')) : null;
  const disasmData = fs.existsSync(disasmPath) ? JSON.parse(fs.readFileSync(disasmPath, 'utf-8')) : null;
  const heapData = fs.existsSync(heapPath) ? JSON.parse(fs.readFileSync(heapPath, 'utf-8')) : null;

  const bundles = collectShowcaseBundles(results);

  const payloadJson = JSON.stringify({
    bundles,
    benchData,
    rwData,
    disasmData,
    heapData,
    allFindings,
    allCbom,
    ruleHumanMap: RULE_HUMAN_MAP,
    containerZhMap: CONTAINER_ZH_MAP,
    formZhMap: FORM_ZH_MAP,
    secretClassZhMap: SECRET_CLASS_ZH_MAP,
    opZhMap: OP_ZH_MAP,
  }).replace(/<\/script>/gi, '<\\/script>');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>鸿钥卫士 KeyScope-HM — 鸿蒙混合应用密钥安全体检与编译器透视平台</title>
  <style>
    :root {
      --bg: #0b1120;
      --sidebar: #0f172a;
      --panel: #151f32;
      --card: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #f43f5e;
      --warn: #f59e0b;
      --ok: #10b981;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Microsoft YaHei", "PingFang SC", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }
    /* 顶部导航栏 */
    .topbar {
      background: linear-gradient(90deg, #0f172a 0%, #172554 100%);
      border-bottom: 1px solid var(--border);
      padding: 14px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand-title { font-size: 20px; font-weight: 800; color: #f8fafc; display: flex; align-items: center; gap: 10px; }
    .brand-sub { font-size: 13px; color: #93c5fd; margin-top: 2px; }
    .guide-steps {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }
    .guide-step {
      background: rgba(56, 189, 248, 0.14);
      border: 1px solid rgba(56, 189, 248, 0.35);
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 12.5px;
      color: #e0f2fe;
    }
    /* 主布局：左侧项目选择栏 + 右侧主内容区 */
    .app-layout {
      display: grid;
      grid-template-columns: 360px 1fr;
      min-height: calc(100vh - 72px);
    }
    @media (max-width: 1180px) {
      .app-layout { grid-template-columns: 1fr; }
    }
    .sidebar {
      background: var(--sidebar);
      border-right: 1px solid var(--border);
      padding: 16px;
      overflow-y: auto;
      max-height: calc(100vh - 72px);
      position: sticky;
      top: 0;
    }
    .side-section-title {
      font-size: 13.5px;
      font-weight: 700;
      color: var(--accent);
      margin: 14px 0 8px 0;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .proj-item {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      margin-bottom: 8px;
      cursor: pointer;
      transition: all 0.15s;
    }
    .proj-item:hover {
      border-color: var(--accent);
      transform: translateX(2px);
    }
    .proj-item.active {
      background: rgba(56, 189, 248, 0.16);
      border-color: var(--accent);
      box-shadow: 0 0 0 1px var(--accent);
    }
    .proj-item-title {
      font-size: 13.5px;
      font-weight: 700;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 6px;
    }
    .proj-item-sub {
      font-size: 12px;
      color: var(--muted);
      margin-top: 4px;
    }
    .pair-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
      margin-bottom: 8px;
    }
    .pair-btns {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      margin-top: 8px;
    }
    .pair-btn {
      padding: 6px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      border: 1px solid var(--border);
      background: #0f172a;
      color: var(--text);
      text-align: center;
    }
    .pair-btn.safe-btn:hover, .pair-btn.safe-btn.active {
      background: rgba(16, 185, 129, 0.22);
      border-color: var(--ok);
      color: #6ee7b7;
    }
    .pair-btn.risky-btn:hover, .pair-btn.risky-btn.active {
      background: rgba(244, 63, 94, 0.22);
      border-color: var(--danger);
      color: #fda4af;
    }
    /* 右侧主舞台 */
    .main-stage {
      padding: 20px 26px;
      overflow-y: auto;
    }
    .tabs {
      display: flex;
      gap: 10px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
      margin-bottom: 18px;
      flex-wrap: wrap;
    }
    .tab-btn {
      background: var(--panel);
      color: var(--muted);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.15s;
    }
    .tab-btn:hover { color: var(--text); border-color: var(--accent); }
    .tab-btn.active {
      background: var(--accent);
      color: #0f172a;
      border-color: var(--accent);
    }
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }
    /* 顶部体检横幅 */
    .summary-banner {
      border-radius: 12px;
      padding: 18px 22px;
      margin-bottom: 18px;
      border: 1px solid var(--border);
    }
    .summary-banner.risky {
      background: linear-gradient(135deg, rgba(244, 63, 94, 0.16) 0%, rgba(30, 41, 59, 0.95) 100%);
      border-color: rgba(244, 63, 94, 0.5);
    }
    .summary-banner.safe {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.16) 0%, rgba(30, 41, 59, 0.95) 100%);
      border-color: rgba(16, 185, 129, 0.5);
    }
    /* 可视化密钥一生流程图 */
    .flow-section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      margin-bottom: 18px;
    }
    .flow-track {
      display: flex;
      align-items: stretch;
      gap: 12px;
      overflow-x: auto;
      padding: 8px 2px;
    }
    .flow-step-card {
      min-width: 240px;
      max-width: 290px;
      background: #0f172a;
      border: 2px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      flex-shrink: 0;
    }
    .flow-step-card.step-origin { border-color: #818cf8; }
    .flow-step-card.step-safe { border-color: var(--ok); }
    .flow-step-card.step-risky { border-color: var(--danger); background: rgba(244, 63, 94, 0.08); }
    .flow-arrow {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      color: var(--accent);
      font-size: 12px;
      min-width: 70px;
      text-align: center;
    }
    /* 诊断卡片与代码修改前后对比 */
    .diag-card {
      background: var(--panel);
      border: 1px solid rgba(244, 63, 94, 0.45);
      border-radius: 12px;
      padding: 18px 20px;
      margin-bottom: 16px;
    }
    .explain-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 12px;
    }
    .explain-box {
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 13.5px;
    }
    .diff-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 12px;
    }
    @media (max-width: 1100px) {
      .explain-grid, .diff-grid { grid-template-columns: 1fr; }
    }
    .diff-box {
      border-radius: 8px;
      padding: 12px;
      font-family: Consolas, "Microsoft YaHei", monospace;
      font-size: 12.5px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    .diff-bad {
      background: rgba(244, 63, 94, 0.1);
      border: 1px solid rgba(244, 63, 94, 0.45);
      color: #fecdd3;
    }
    .diff-good {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.45);
      color: #d1fae5;
    }
    /* 三栏编译器对照视图 */
    .compiler-grid {
      display: grid;
      grid-template-columns: 1.05fr 1.05fr 1fr;
      gap: 12px;
    }
    @media (max-width: 1360px) {
      .compiler-grid { grid-template-columns: 1fr; }
    }
    .pane-box {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      display: flex;
      flex-direction: column;
      height: 600px;
      overflow: hidden;
    }
    .pane-header {
      padding: 11px 14px;
      background: rgba(30, 41, 59, 0.9);
      border-bottom: 1px solid var(--border);
      font-size: 13.5px;
      font-weight: 700;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .pane-body {
      padding: 10px;
      overflow-y: auto;
      flex: 1;
      font-family: Consolas, "Microsoft YaHei", monospace;
      font-size: 12.5px;
    }
    .code-line {
      display: flex;
      padding: 3px 6px;
      border-radius: 4px;
      cursor: pointer;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .code-line:hover { background: rgba(56, 189, 248, 0.15); }
    .code-line.hl-line { background: rgba(244, 63, 94, 0.22); border-left: 3px solid var(--danger); }
    .code-line.hl-active { background: rgba(56, 189, 248, 0.28); border-left: 3px solid var(--accent); }
    .ln-num { width: 38px; color: var(--muted); user-select: none; flex-shrink: 0; }
    .badge {
      display: inline-block;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 11.5px;
      font-weight: 700;
    }
    .badge-danger { background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid #f43f5e; }
    .badge-warn { background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid #f59e0b; }
    .badge-ok { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid #10b981; }
    .badge-info { background: rgba(56, 189, 248, 0.18); color: #7dd3fc; border: 1px solid #0284c7; }
    .bar-wrap {
      background: #0f172a;
      border-radius: 999px;
      height: 18px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .bar-fill { height: 100%; border-radius: 999px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { background: rgba(15, 23, 42, 0.75); color: #cbd5e1; font-weight: 700; }
    .btn {
      background: var(--accent);
      color: #0f172a;
      border: none;
      border-radius: 8px;
      padding: 8px 14px;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
    }
    .sandbox-modal {
      display: none;
      background: var(--card);
      border: 2px solid var(--accent);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 18px;
    }
    .sandbox-modal.open { display: block; }
    textarea {
      width: 100%;
      height: 180px;
      background: #090d16;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      font-family: Consolas, monospace;
      font-size: 12.5px;
    }
  </style>
</head>
<body>
  <!-- 顶部中文导航与三步操作指引 -->
  <div class="topbar">
    <div>
      <div class="brand-title">🛡️ 鸿钥卫士 KeyScope-HM — 鸿蒙混合应用密钥安全体检与编译器透视平台</div>
      <div class="brand-sub">自动追踪一把密钥在“鸿蒙界面层 (ArkTS) ⇄ C++ 原生层 (NAPI) ⇄ 硬件安全芯片 (HUKS)”中的完整一生</div>
    </div>
    <div class="guide-steps">
      <div class="guide-step"><b>第 1 步：</b>在左侧点击要查看的<b>鸿蒙项目或安全/危险对比场景</b></div>
      <div class="guide-step"><b>第 2 步：</b>在右侧看<b>密钥流转全景图与大白话诊断书</b></div>
      <div class="guide-step"><b>第 3 步：</b>切换标签页查看<b>编译器底层拆解与内存取证实验</b></div>
    </div>
  </div>

  <div class="app-layout">
    <!-- 左侧常驻项目与场景选择栏 -->
    <aside class="sidebar">
      <button class="btn" style="width:100%;margin-bottom:10px;" onclick="toggleSandboxModal()">
        ✍️ 粘贴/编写你自己的鸿蒙代码立即体检
      </button>

      <div class="side-section-title">
        <span>🏢 一、8 个真实开源鸿蒙项目体检报告</span>
        <span style="font-size:11px;color:var(--muted);">点击即看</span>
      </div>
      <div id="realworldSidebarList"></div>

      <div class="side-section-title" style="margin-top:18px;">
        <span>⚖️ 二、8 大典型场景“安全 vs 危险”对比</span>
        <span style="font-size:11px;color:var(--muted);">一键切换</span>
      </div>
      <div id="scenarioPairsSidebarList"></div>
    </aside>

    <!-- 右侧主内容区 -->
    <main class="main-stage">
      <!-- 在线自定义代码沙盒弹窗 -->
      <div id="sandboxModal" class="sandbox-modal">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
          <div>
            <b style="font-size:15px;color:var(--accent);">✍️ 自定义鸿蒙 ArkTS + C++ 密钥安全实时检测沙盒</b>
            <div style="font-size:12px;color:var(--muted);">修改下方代码后点击右侧按钮，系统将实时调用鸿蒙 ArkAnalyzer 与 Clang 语法树引擎为您生成白话体检报告</div>
          </div>
          <div style="display:flex;gap:8px;">
            <button class="btn" onclick="runLiveSandbox()">▶ 立即开始代码体检</button>
            <button class="btn" style="background:#334155;color:#f8fafc;" onclick="toggleSandboxModal()">收起</button>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div>
            <div style="font-size:12.5px;margin-bottom:4px;font-weight:700;">鸿蒙界面层代码 (ArkTS <code>.ets</code>)：</div>
            <textarea id="sandboxEts">import nativeCrypto from 'libcrypto.so';
import util from '@ohos.util';

export function deriveAndEncode(): string {
  const keyBuf: Uint8Array = nativeCrypto.deriveKeyBad();
  const b64 = new util.Base64Helper();
  return b64.encodeToStringSync(keyBuf);
}</textarea>
          </div>
          <div>
            <div style="font-size:12.5px;margin-bottom:4px;font-weight:700;">C++ 原生层代码 (Native <code>.cpp</code>)：</div>
            <textarea id="sandboxCpp">#include &lt;napi/native_api.h&gt;
#include &lt;openssl/evp.h&gt;
static napi_value DeriveKeyBad(napi_env env, napi_callback_info info) {
  EVP_PKEY_CTX *ctx = nullptr;
  unsigned char *out = static_cast&lt;unsigned char *&gt;(OPENSSL_malloc(32));
  size_t len = 32;
  EVP_PKEY_derive(ctx, out, &amp;len);
  napi_value result;
  void *dst = nullptr;
  napi_create_buffer_copy(env, len, out, &amp;dst, &amp;result);
  OPENSSL_free(out);
  return result;
}
static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
    { "deriveKeyBad", nullptr, DeriveKeyBad, nullptr, nullptr, nullptr, napi_default, nullptr }
  };
  napi_define_properties(env, exports, 1, desc);
  return exports;
}</textarea>
          </div>
        </div>
      </div>

      <!-- 四大主功能视图切换标签 -->
      <div class="tabs">
        <button id="btn-tab-diagnosis" class="tab-btn active" onclick="switchTab('tab-diagnosis', this)">
          🔍 1. 密钥安全体检与白话诊断书（推荐首看）
        </button>
        <button id="btn-tab-compiler" class="tab-btn" onclick="switchTab('tab-compiler', this)">
          ⚙️ 2. 源码与编译器底层视角对照（三栏联动透视）
        </button>
        <button id="btn-tab-lab" class="tab-btn" onclick="switchTab('tab-lab', this)">
          🧪 3. 眼见为实：内存残留与编译器优化物理实验室
        </button>
        <button id="btn-tab-overview" class="tab-btn" onclick="switchTab('tab-overview', this)">
          📊 4. 全部项目体检总表 &amp; 加密算法清单 (CBOM)
        </button>
      </div>

      <!-- 视图 1：密钥安全体检与白话诊断书 -->
      <div id="tab-diagnosis" class="tab-pane active">
        <div id="projectSummaryBanner"></div>

        <div class="flow-section">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;">
            <div>
              <b style="font-size:16px;color:var(--accent);">🗺️ 一图看懂：当前项目里“密钥的一生”去了哪里？</b>
              <div style="font-size:12.5px;color:var(--muted);">系统自动追踪每把密钥从【诞生】到【转换/传递】再到【最终位置与是否擦除】的全过程（点击卡片可跳转到对应源码）</div>
            </div>
          </div>
          <div id="visualLifecycleContainer"></div>
        </div>

        <div id="plainFindingsContainer"></div>
      </div>

      <!-- 视图 2：源码与编译器底层视角对照 -->
      <div id="tab-compiler" class="tab-pane">
        <div style="background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
          <div>
            <b style="color:var(--accent);">🔬 为什么传统工具抓不到这些漏洞，而本系统能抓到？</b>
            <span style="font-size:13px;color:var(--muted);margin-left:8px;">因为本系统同时拆解了【鸿蒙 ArkTS 编译器三地址指令】与【C++ Clang 抽象语法树】，把跨语言传递和内存清零看得一清二楚。</span>
          </div>
          <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:13px;font-weight:700;">切换当前项目源码文件：</span>
            <select id="fileSelect" onchange="renderSelectedSourceFile()" style="background:#090d16;color:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:6px 10px;"></select>
          </div>
        </div>

        <div class="compiler-grid">
          <div class="pane-box">
            <div class="pane-header">
              <span>📄 左栏：应用源代码 (点击任意行与右侧指令联动高亮)</span>
              <span style="font-size:11.5px;color:#fda4af;">红底行 = 检出风险位置</span>
            </div>
            <div id="sourcePaneBody" class="pane-body"></div>
          </div>

          <div class="pane-box">
            <div class="pane-header">
              <span>⚙️ 中栏：鸿蒙编译器底层执行步骤拆解 (ArkAnalyzer IR)</span>
              <span id="apakHeaderMeta" style="font-size:11.5px;color:#7dd3fc;"></span>
            </div>
            <div id="irPaneBody" class="pane-body"></div>
          </div>

          <div class="pane-box">
            <div class="pane-header">
              <span>🔗 右栏：C++ 跨语言桥接与语法树拆解 (Clang AST)</span>
              <span id="clangHeaderMeta" style="font-size:11.5px;color:#6ee7b7;"></span>
            </div>
            <div id="astPaneBody" class="pane-body"></div>
          </div>
        </div>
      </div>

      <!-- 视图 3：内存残留与编译器优化物理实验室 -->
      <div id="tab-lab" class="tab-pane">
        <div id="physicalLabContainer"></div>
      </div>

      <!-- 视图 4：全部项目体检总表 & 加密算法清单 -->
      <div id="tab-overview" class="tab-pane">
        <div id="overviewTablesContainer"></div>
      </div>
    </main>
  </div>
`;
}
