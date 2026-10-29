/**
 * report/report_generator.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 多模态报告生成器
 *
 * 支持输出：
 * 1. 交互式跨运行时密钥表示溯源图 HTML 报告 (keyscope_report.html)
 * 2. OASIS SARIF 2.1.0 静态分析标准报告 (keyscope_results.sarif.json)
 * 3. OWASP CycloneDX 1.6 密码物料清单报告 (keyscope_cbom.cdx.json)
 */

import * as fs from 'fs';
import * as path from 'path';
import { AnalysisResult } from '../core-ts/analysis/repflow';
import { GradedFinding } from '../core-ts/grade';
import { CryptoAssetItem } from '../core-ts/repr';
import { renderInteractiveWorkbenchHtml } from './workbench_template';

export interface GeneratedReportPaths {
  htmlPath: string;
  sarifPath: string;
  cbomPath: string;
}

const RULE_META: Record<
  string,
  { name: string; shortDescription: string; helpUri: string; defaultLevel: 'error' | 'warning' }
> = {
  V1: {
    name: 'KeyMaterialInImmutableString',
    shortDescription: 'V1: 可恢复密钥材料进入不可变托管字符串容器 (ArkString / D_mem)',
    helpUri: 'https://cwe.mitre.org/data/definitions/316.html',
    defaultLevel: 'error',
  },
  V2: {
    name: 'KeyMaterialInUntrustedPersistenceOrIPC',
    shortDescription: 'V2: 可恢复密钥材料未经受控包装落入持久化存储或跨进程通道 (D_pers / D_ipc)',
    helpUri: 'https://cwe.mitre.org/data/definitions/312.html',
    defaultLevel: 'error',
  },
  V3: {
    name: 'KeyMaterialInLogSink',
    shortDescription: 'V3: 可恢复密钥材料或其编码表示输出至日志通道 (D_log)',
    helpUri: 'https://cwe.mitre.org/data/definitions/532.html',
    defaultLevel: 'error',
  },
  E1_M4: {
    name: 'MissingOrEliminatedBufferZeroization',
    shortDescription: 'E1(M4): 原始密钥缓冲区缺失路径必达清零或使用易被编译器 DSE 消除的普通 memset',
    helpUri: 'https://cwe.mitre.org/data/definitions/226.html',
    defaultLevel: 'warning',
  },
  E2_M3: {
    name: 'AEADStaticOrReusedNonce',
    shortDescription: 'E2(M3): 认证加密模式 (GCM/CCM/CTR) 静态或跨次复用 IV/Nonce',
    helpUri: 'https://cwe.mitre.org/data/definitions/323.html',
    defaultLevel: 'error',
  },
  E3_M2: {
    name: 'HuksPreImportPlaintextExposure',
    shortDescription: 'E3(M2): 明文密钥在导入 HUKS 硬件边界前存在不可清零驻留或暴露链',
    helpUri: 'https://cwe.mitre.org/data/definitions/312.html',
    defaultLevel: 'warning',
  },
};

/**
 * 生成 OASIS SARIF 2.1.0 报告对象
 */
export function buildSarifReport(results: AnalysisResult[]): Record<string, unknown> {
  const sarifResults: Array<Record<string, unknown>> = [];

  for (const res of results) {
    for (const f of res.findings) {
      const threadLocations = [
        {
          location: {
            physicalLocation: {
              artifactLocation: {
                uri: f.file.replace(/\\/g, '/'),
              },
              region: {
                startLine: Math.max(1, f.line),
              },
            },
            message: {
              text: `[Secret: ${f.secretId} (${f.secretClass})] -> Repr ${f.reprId} [form=${f.form}, container=${f.container}]`,
            },
          },
        },
        ...f.provenancePath.map((edge) => ({
          location: {
            physicalLocation: {
              artifactLocation: {
                uri: edge.file.replace(/\\/g, '/'),
              },
              region: {
                startLine: Math.max(1, edge.line),
              },
            },
            message: {
              text: `${edge.from} --[${edge.op}]--> ${edge.to} (${edge.detail ?? edge.site})`,
            },
          },
        })),
      ];

      sarifResults.push({
        ruleId: f.rule,
        level: f.grade === 'High' ? 'error' : f.grade === 'Medium' ? 'warning' : 'note',
        message: {
          text: `[${res.projectName}] ${f.reason} (Remediation: ${f.remediation})`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: f.file.replace(/\\/g, '/'),
              },
              region: {
                startLine: Math.max(1, f.line),
              },
            },
          },
        ],
        codeFlows: [
          {
            message: {
              text: `Representation Provenance Chain for ${f.secretId}`,
            },
            threadFlows: [
              {
                locations: threadLocations,
              },
            ],
          },
        ],
        properties: {
          project: res.projectName,
          findingId: f.id,
          cwe: f.cwe,
          confidenceGrade: f.grade,
          secretId: f.secretId,
          secretClass: f.secretClass,
          reprId: f.reprId,
          form: f.form,
          container: f.container,
          exposureDomain: f.domain,
        },
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'KeyScope-HM',
            fullName: 'KeyScope-HM v3.0: Cross-Runtime Key Representation & Exposure Analyzer for HarmonyOS',
            semanticVersion: '3.0.0',
            informationUri: 'https://gitee.com/openharmony-sig/arkanalyzer',
            rules: Object.entries(RULE_META).map(([id, meta]) => ({
              id,
              name: meta.name,
              shortDescription: { text: meta.shortDescription },
              helpUri: meta.helpUri,
              defaultConfiguration: { level: meta.defaultLevel },
            })),
          },
        },
        results: sarifResults,
      },
    ],
  };
}

/**
 * 生成 OWASP CycloneDX 1.6 CBOM (Cryptography Bill of Materials) 报告对象
 */
export function buildCbomReport(results: AnalysisResult[]): Record<string, unknown> {
  const components: Array<Record<string, unknown>> = [];
  let totalAssets = 0;
  let quantumVulnerableCount = 0;
  let weakAlgorithmCount = 0;
  let gmCompliantCount = 0;

  for (const res of results) {
    for (const asset of res.cbomAssets) {
      totalAssets++;
      if (asset.quantumVulnerable) quantumVulnerableCount++;
      if (asset.weakAlgorithm) weakAlgorithmCount++;
      if (asset.gmCompliant) gmCompliantCount++;

      components.push({
        type: 'cryptographic-asset',
        'bom-ref': `${res.projectName}::${asset.id}`,
        name: asset.algorithm,
        version: '1.0',
        description: `Cryptographic primitive (${asset.primitive}) invoked at ${asset.site} in project ${res.projectName}`,
        cryptoProperties: {
          assetType: 'algorithm',
          algorithmProperties: {
            primitive: asset.primitive,
            parameterSetIdentifier: asset.keySize ? String(asset.keySize) : undefined,
            mode: asset.mode ? asset.mode.toLowerCase() : undefined,
            padding: asset.padding ? asset.padding.toLowerCase() : undefined,
            nistQuantumSecurityLevel: asset.quantumVulnerable ? 0 : asset.keySize && asset.keySize >= 256 ? 5 : 1,
          },
        },
        evidence: {
          occurrences: [
            {
              location: asset.file.replace(/\\/g, '/'),
              line: asset.line,
            },
          ],
        },
        properties: [
          { name: 'keyscope:project', value: res.projectName },
          { name: 'keyscope:site', value: asset.site },
          { name: 'keyscope:quantumVulnerable', value: String(asset.quantumVulnerable) },
          { name: 'keyscope:weakAlgorithm', value: String(asset.weakAlgorithm) },
          { name: 'keyscope:gmCompliant', value: String(asset.gmCompliant) },
          { name: 'keyscope:hndlScore', value: String(asset.hndlScore) },
        ],
      });
    }

    // 同步将分析发现的逻辑秘密 κ 作为 related-crypto-material 写入 CBOM
    for (const sec of res.facts.secrets.values()) {
      components.push({
        type: 'cryptographic-asset',
        'bom-ref': `${res.projectName}::${sec.id}`,
        name: sec.id,
        description: sec.originDesc ?? `Logical secret (${sec.cls}) at ${sec.site}`,
        cryptoProperties: {
          assetType: 'related-crypto-material',
          relatedCryptoMaterialProperties: {
            type: sec.cls === 'LongTerm' ? 'private-key' : 'secret-key',
            state: sec.cls === 'HardwareBound' ? 'active' : 'in-use',
          },
        },
        properties: [
          { name: 'keyscope:project', value: res.projectName },
          { name: 'keyscope:secretClass', value: sec.cls },
          { name: 'keyscope:site', value: sec.site },
        ],
      });
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:keyscope-hm-v3-${Date.now()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'KeyScope-HM',
            version: '3.0.0',
            description: 'HarmonyOS Hybrid Application Cross-Runtime Key Representation & CBOM Analyzer',
          },
        ],
      },
      properties: [
        { name: 'keyscope:totalCryptoAlgorithms', value: String(totalAssets) },
        { name: 'keyscope:quantumVulnerableCount', value: String(quantumVulnerableCount) },
        { name: 'keyscope:weakAlgorithmCount', value: String(weakAlgorithmCount) },
        { name: 'keyscope:gmCompliantCount', value: String(gmCompliantCount) },
      ],
    },
    components,
  };
}

/**
 * 生成包含交互式表示溯源图 (Provenance Graph)、告警详情与修复对比模板的 HTML 报告
 */
export function buildHtmlReport(results: AnalysisResult[]): string {
  const allFindings: Array<{ project: string; finding: GradedFinding }> = [];
  const allCbom: Array<{ project: string; asset: CryptoAssetItem }> = [];

  for (const r of results) {
    for (const f of r.findings) {
      allFindings.push({ project: r.projectName, finding: f });
    }
    for (const a of r.cbomAssets) {
      allCbom.push({ project: r.projectName, asset: a });
    }
  }

  return renderInteractiveWorkbenchHtml(results, allFindings, allCbom);
}

/**
 * 将 HTML、SARIF 2.1.0、CycloneDX 1.6 CBOM 报告写入指定输出目录
 */
export function generateAllReports(
  results: AnalysisResult | AnalysisResult[],
  outputDir: string
): GeneratedReportPaths {
  const list = Array.isArray(results) ? results : [results];
  fs.mkdirSync(outputDir, { recursive: true });

  const htmlPath = path.join(outputDir, 'keyscope_report.html');
  const sarifPath = path.join(outputDir, 'keyscope_results.sarif.json');
  const cbomPath = path.join(outputDir, 'keyscope_cbom.cdx.json');

  fs.writeFileSync(htmlPath, buildHtmlReport(list), 'utf-8');
  fs.writeFileSync(sarifPath, JSON.stringify(buildSarifReport(list), null, 2), 'utf-8');
  fs.writeFileSync(cbomPath, JSON.stringify(buildCbomReport(list), null, 2), 'utf-8');

  return { htmlPath, sarifPath, cbomPath };
}
