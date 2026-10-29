/**
 * baselines/b0_regex_entropy.ts
 * 基线 B0 (对应 v2 Baseline A)：传统正则匹配 + 信息熵 (Shannon Entropy) + 变量命名启发式扫描器
 */

import * as fs from 'fs';
import * as path from 'path';

export interface BaselineFinding {
  rule: string;
  file: string;
  line: number;
  reason: string;
}

function shannonEntropy(s: string): number {
  if (!s || s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let ent = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

export function runBaselineB0(projectDir: string): BaselineFinding[] {
  const findings: BaselineFinding[] = [];
  const suspiciousVars = new Set<string>();

  const walk = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        walk(full);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith('.ets') ||
          entry.name.endsWith('.ts') ||
          entry.name.endsWith('.cpp')) &&
        !entry.name.endsWith('.d.ts')
      ) {
        scanFileB0(full, findings, suspiciousVars);
      }
    }
  };

  walk(projectDir);
  return findings;
}

function scanFileB0(
  filePath: string,
  findings: BaselineFinding[],
  suspiciousVars: Set<string>
): void {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = lines[i].trim();
    if (!line || line.startsWith('//')) continue;

    // 1. 识别命名中含有 secret / key / private / token 的变量定义
    const mVar = line.match(
      /\b(?:let|const|var|uint8_t|char)\s+([A-Za-z0-9_]*(?:secret|key|token|passwd)[A-Za-z0-9_]*)/i
    );
    if (mVar) {
      suspiciousVars.add(mVar[1]);
    }

    // 2. 识别高信息熵字符串字面量 (长度 >= 16 且熵 >= 3.4 或含十六进制特征)
    const strMatches = line.matchAll(/['"]([A-Za-z0-9+/=_:-]{16,})['"]/g);
    for (const sm of strMatches) {
      const lit = sm[1];
      if (shannonEntropy(lit) >= 3.4 && /[0-9a-f]{8}/i.test(lit)) {
        findings.push({
          rule: 'B0_HighEntropyLiteral',
          file: filePath,
          line: lineNo,
          reason: `检测到高信息熵疑似密钥字面量 '${lit.slice(0, 20)}...' (H=${shannonEntropy(lit).toFixed(2)})`,
        });
      }
    }

    // 3. 简单变量传递 (1跳命名传播)
    const mAssign = line.match(/\b(?:let|const|var)?\s*([A-Za-z0-9_.]+)\s*=\s*([A-Za-z0-9_.]+)/);
    if (mAssign && suspiciousVars.has(mAssign[2])) {
      suspiciousVars.add(mAssign[1]);
    }

    // 4. 正则匹配 Sink 点 (putSync / hilog / napi_create_string_utf8 / memset)
    if (/napi_create_string_utf8/.test(line)) {
      findings.push({
        rule: 'B0_NapiString',
        file: filePath,
        line: lineNo,
        reason: '正则匹配到 napi_create_string_utf8 调用',
      });
    }

    if (/\bmemset\s*\(/.test(line) && !/\bmemset_s\s*\(/.test(line)) {
      findings.push({
        rule: 'B0_PlainMemset',
        file: filePath,
        line: lineNo,
        reason: '正则匹配到普通 memset 调用',
      });
    }

    const mSink = line.match(/\b(?:putSync|put|info|warn|error|log|stringify)\s*\(([^)]*)\)/);
    if (mSink) {
      const argsText = mSink[1];
      for (const sv of suspiciousVars) {
        if (new RegExp(`\\b${sv.replace('.', '\\.')}\\b`).test(argsText)) {
          findings.push({
            rule: 'B0_SuspiciousVarInSink',
            file: filePath,
            line: lineNo,
            reason: `疑似密钥命名的变量 '${sv}' 流入外部 Sink`,
          });
        }
      }
    }
  }
}
