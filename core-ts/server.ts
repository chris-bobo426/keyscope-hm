/**
 * core-ts/server.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 交互式编译器 IR / Clang AST / LSR 溯源图可视化分析工作台服务
 *
 * 启动方式：
 *   npm run ui
 *   (默认监听 http://localhost:3000 ，支持 --port <number> 与 --check 自检模式)
 */

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { analyzeProject, AnalysisResult } from './analysis/repflow';
import { buildHtmlReport } from '../report/report_generator';

export interface ProjectInspectPayload {
  projectName: string;
  projectDir: string;
  durationMs: number;
  arkFilesCount: number;
  cppFilesCount: number;
  methodsAnalyzed: number;
  apakStats: AnalysisResult['apakStats'];
  sourceFiles: Array<{
    relPath: string;
    lang: 'ets' | 'cpp';
    content: string;
  }>;
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
  cbomAssets: AnalysisResult['cbomAssets'];
}

function collectSourceFiles(projectDir: string): Array<{ relPath: string; lang: 'ets' | 'cpp'; content: string }> {
  const out: Array<{ relPath: string; lang: 'ets' | 'cpp'; content: string }> = [];
  function walk(dir: string): void {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        walk(full);
      } else if (entry.isFile()) {
        if (entry.name.endsWith('.ets') || entry.name.endsWith('.ts')) {
          out.push({
            relPath: path.relative(projectDir, full).replace(/\\/g, '/'),
            lang: 'ets',
            content: fs.readFileSync(full, 'utf-8'),
          });
        } else if (
          entry.name.endsWith('.cpp') ||
          entry.name.endsWith('.cc') ||
          entry.name.endsWith('.c') ||
          entry.name.endsWith('.h')
        ) {
          out.push({
            relPath: path.relative(projectDir, full).replace(/\\/g, '/'),
            lang: 'cpp',
            content: fs.readFileSync(full, 'utf-8'),
          });
        }
      }
    }
  }
  walk(projectDir);
  return out.slice(0, 25);
}

export function serializeAnalysisResult(res: AnalysisResult): ProjectInspectPayload {
  return {
    projectName: res.projectName,
    projectDir: res.projectDir,
    durationMs: res.durationMs,
    arkFilesCount: res.arkFilesCount,
    cppFilesCount: res.cppFilesCount,
    methodsAnalyzed: res.methodsAnalyzed,
    apakStats: res.apakStats,
    sourceFiles: collectSourceFiles(res.projectDir),
    irDump: res.irDump,
    napiDetails: res.napiDetails,
    secrets: Array.from(res.facts.secrets.values()),
    reprs: Array.from(res.facts.reprs.values()).map((r) => ({
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
    cbomAssets: res.cbomAssets,
  };
}

export function createKeyScopeServer(): http.Server {
  const rootDir = path.resolve(__dirname, '..');
  const benchSamplesDir = path.join(rootDir, 'bench', 'samples');
  const realworldReposDir = path.join(rootDir, 'realworld', 'repos');
  const reportHtmlPath = path.join(rootDir, 'report', 'output', 'keyscope_report.html');

  return http.createServer((req, res) => {
    const urlObj = new URL(req.url ?? '/', 'http://localhost');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && (urlObj.pathname === '/' || urlObj.pathname === '/index.html')) {
      if (fs.existsSync(reportHtmlPath)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(fs.readFileSync(reportHtmlPath, 'utf-8'));
      } else {
        const sampleRes = analyzeProject(path.join(benchSamplesDir, 'F3_v1_direct_B_Risky'));
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildHtmlReport([sampleRes]));
      }
      return;
    }

    if (req.method === 'GET' && urlObj.pathname === '/api/projects') {
      const benchList = fs.existsSync(benchSamplesDir)
        ? fs
            .readdirSync(benchSamplesDir, { withFileTypes: true })
            .filter((d) => d.isDirectory())
            .map((d) => ({
              id: `bench/${d.name}`,
              name: d.name,
              category: 'HarmonyKeyRepBench (64 Samples)',
              path: path.join(benchSamplesDir, d.name),
            }))
        : [];
      const rwList = fs.existsSync(realworldReposDir)
        ? fs
            .readdirSync(realworldReposDir, { withFileTypes: true })
            .filter((d) => d.isDirectory())
            .map((d) => ({
              id: `realworld/${d.name}`,
              name: d.name,
              category: 'OpenHarmony Real-World Repos (8 Projects)',
              path: path.join(realworldReposDir, d.name),
            }))
        : [];
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ projects: [...benchList, ...rwList] }));
      return;
    }

    if (req.method === 'GET' && urlObj.pathname === '/api/inspect') {
      const targetId = urlObj.searchParams.get('id') ?? 'bench/F3_v1_direct_B_Risky';
      const [group, name] = targetId.split('/');
      const baseDir = group === 'realworld' ? realworldReposDir : benchSamplesDir;
      const targetDir = path.resolve(baseDir, name ?? '');
      if (!targetDir.startsWith(baseDir) || !fs.existsSync(targetDir)) {
        res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: `Project not found: ${targetId}` }));
        return;
      }
      try {
        const result = analyzeProject(targetDir);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(serializeAnalysisResult(result)));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: String(err) }));
      }
      return;
    }

    if (req.method === 'POST' && urlObj.pathname === '/api/sandbox') {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body || '{}') as {
            etsCode?: string;
            cppCode?: string;
            projectName?: string;
          };
          const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'keyscope-live-sandbox-'));
          const etsDir = path.join(tmpRoot, 'entry', 'src', 'main', 'ets');
          const cppDir = path.join(tmpRoot, 'entry', 'src', 'main', 'cpp');
          fs.mkdirSync(etsDir, { recursive: true });
          if (payload.etsCode && payload.etsCode.trim().length > 0) {
            fs.writeFileSync(path.join(etsDir, 'SandboxIndex.ets'), payload.etsCode, 'utf-8');
          }
          if (payload.cppCode && payload.cppCode.trim().length > 0) {
            fs.mkdirSync(cppDir, { recursive: true });
            fs.writeFileSync(path.join(cppDir, 'napi_sandbox.cpp'), payload.cppCode, 'utf-8');
          }
          const result = analyzeProject(tmpRoot);
          result.projectName = payload.projectName || 'Live_Sandbox_Project';
          const serialized = serializeAnalysisResult(result);
          fs.rmSync(tmpRoot, { recursive: true, force: true });
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify(serialized));
        } catch (err) {
          res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ error: String(err) }));
        }
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const portIdx = args.indexOf('--port');
  const port = portIdx >= 0 && args[portIdx + 1] ? Number(args[portIdx + 1]) : 3000;
  const isCheckOnly = args.includes('--check');

  const srv = createKeyScopeServer();
  srv.listen(port, '127.0.0.1', () => {
    console.log('================================================================================');
    console.log(`鸿钥卫士 KeyScope-HM v3.0 — 交互式编译器 IR / AST / 溯源图分析工作台已启动`);
    console.log(`访问地址: http://localhost:${port}`);
    console.log(`API 接口: GET /api/projects | GET /api/inspect?id=... | POST /api/sandbox`);
    console.log('================================================================================');
    if (isCheckOnly) {
      srv.close(() => process.exit(0));
    }
  });
}
