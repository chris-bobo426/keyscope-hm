/**
 * core-ts/analysis/repflow.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 基于 ArkAnalyzer (ArkIR + APAK) 的跨运行时密钥表示传播算法 (RepFlow)
 *
 * 核心特性：
 * 1. 对接 OpenHarmony 官方静态分析框架 ArkAnalyzer (Scene / Cfg / Stmt / APAK IPagPlugin)；
 * 2. 将密码学、NAPI、存储、IPC、日志 API 建模为表示对象 (Repr) 的创建与转换规则；
 * 3. 支持 1-call-site 上下文敏感堆克隆（防止 toHex 等共用辅助函数混淆公开 IV 与秘密密钥）；
 * 4. 支持对象字段敏感 (fld) 与结构体序列化 (JSON.stringify)；
 * 5. 支持分支汇合点指向集合并集 (pts union)，保留多秘密身份 (κ)；
 * 6. 同步采集 E1(清零)、E2(GCM Nonce 复用)、E3(HUKS 导入前暴露) 与 M6(CBOM 密码资产)。
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  Scene,
  SceneConfig,
  ArkMethod,
  Stmt,
  ArkAssignStmt,
  ArkInvokeStmt,
  ArkReturnStmt,
  AbstractInvokeExpr,
  ArkInstanceInvokeExpr,
  ArkStaticInvokeExpr,
  ArkPtrInvokeExpr,
  ArkNewExpr,
  ArkNewArrayExpr,
  ArkAwaitExpr,
  ArkCastExpr,
  ArkUnopExpr,
  AbstractBinopExpr,
  ArkPhiExpr,
  ArkInstanceFieldRef,
  ArkStaticFieldRef,
  ArkArrayRef,
  ArkParameterRef,
  Local,
  Constant,
  Value,
  Pag,
  PagBuilder,
  PointerAnalysisConfig,
  CallGraph,
  CallGraphNode,
  ICallSite,
} from 'arkanalyzer';
import { IPagPlugin } from 'arkanalyzer/lib/callgraph/pointerAnalysis/plugins/IPagPlugin';

import {
  Facts,
  AnalysisOptions,
  SecretClass,
  Form,
  EncodingKind,
  Container,
  CryptoAssetItem,
} from '../repr';
import {
  introduceSecret,
  introduceHuksKeyAndHandle,
  convertRepr,
  aliasRepr,
  wrapRepr,
  oneWayRepr,
  serializeObjectRepr,
  SiteLocation,
} from '../rules/transfer';
import {
  buildProjectNapiSummaries,
  instantiateNapiSummary,
  NapiFunctionSummary,
} from '../bridge/napi_bridge';
import { computeRec, checkPolicyViolations } from '../rec';
import { gradeViolations, GradedFinding } from '../grade';
import { inspectRealWorldProjectFacts } from './realworld_inspector';

/**
 * G1 关口验证组件：ArkAnalyzer APAK 指针分析插件接口实现 (IPagPlugin)
 * 可直接注册至 APAK PluginManager 以拦截密码学与跨语言 API 调用点
 */
export class KeyScopeApakPlugin implements IPagPlugin {
  pag: Pag;
  pagBuilder: PagBuilder;
  cg: CallGraph;
  interceptedCalls: Array<{ methodName: string; cid: number; site: string }> = [];

  constructor(pag: Pag, pagBuilder: PagBuilder, cg: CallGraph) {
    this.pag = pag;
    this.pagBuilder = pagBuilder;
    this.cg = cg;
  }

  getName(): string {
    return 'KeyScopeRepFlowPagPlugin';
  }

  canHandle(cs: ICallSite, cgNode: CallGraphNode): boolean {
    const mName = cgNode?.getMethod()?.getMethodSubSignature()?.getMethodName() ?? '';
    return (
      mName.includes('Key') ||
      mName.includes('encode') ||
      mName.includes('put') ||
      mName.includes('init') ||
      mName.includes('wrap')
    );
  }

  processCallSite(cs: ICallSite, cid: number, _basePTNode: number): number[] {
    const line = cs.callStmt?.getOriginPositionInfo()?.getLineNo() ?? -1;
    const mName = cs.callStmt?.getInvokeExpr()?.getMethodSignature()?.getMethodSubSignature()?.getMethodName() ?? 'unknown';
    this.interceptedCalls.push({ methodName: mName, cid, site: `line:${line}` });
    return [];
  }
}

export interface IrStmtDump {
  idx: number;
  line: number;
  kind: string;
  text: string;
}

export interface IrMethodDump {
  methodKey: string;
  file: string;
  line: number;
  stmts: IrStmtDump[];
}

export interface ApakExecutionStats {
  cgNodesCount: number;
  pagNodesCount: number;
  interceptedCalls: Array<{ methodName: string; cid: number; site: string }>;
}

export interface AnalysisResult {
  projectDir: string;
  projectName: string;
  arkFilesCount: number;
  cppFilesCount: number;
  methodsAnalyzed: number;
  napiSummariesCount: number;
  durationMs: number;
  facts: Facts;
  findings: GradedFinding[];
  cbomAssets: CryptoAssetItem[];
  apakStats: ApakExecutionStats;
  irDump: IrMethodDump[];
  napiDetails: NapiFunctionSummary[];
}

interface MethodSummaryInfo {
  method: ArkMethod;
  name: string;
  className: string;
  filePath: string;
  isConversionHelper: boolean;
}

/**
 * 判断函数名是否属于自定义的十六进制/Base64/字符串编码辅助函数
 */
function isHelperEncoderName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === 'tohex' ||
    lower === 'bytestohex' ||
    lower === 'uint8arraytohex' ||
    lower === 'buffertohex' ||
    lower === 'hexencode' ||
    lower === 'tobase64' ||
    lower === 'bytestostring' ||
    lower === 'uint8arraytostring' ||
    lower === 'formatkeystring'
  );
}

/**
 * 从算法字符串（如 'SM4_128|GCM|NoPadding', 'AES128|CBC|PKCS7', 'RSA2048|PKCS1', 'SHA256', 'MD5'）解析密码资产
 */
function parseCryptoAlgorithmSpec(
  algSpec: string,
  file: string,
  line: number
): CryptoAssetItem | null {
  const clean = algSpec.replace(/^['"`]|['"`]$/g, '').trim();
  if (!clean) return null;

  const upper = clean.toUpperCase();
  const isCrypto =
    /^(AES|SM4|3DES|DES|RSA|ECC|SM2|ECDH|X25519|DH|SHA|MD5|SM3|HMAC|PBKDF2|HKDF)/.test(upper);
  if (!isCrypto) return null;

  const parts = clean.split('|');
  const algPart = parts[0];
  const mode = parts[1];
  const padding = parts[2];

  const keySizeMatch = algPart.match(/(\d{2,4})$/);
  const keySize = keySizeMatch ? parseInt(keySizeMatch[1], 10) : undefined;

  let primitive: CryptoAssetItem['primitive'] = 'symmetric';
  if (/^(RSA|ECC|SM2)/.test(upper)) primitive = 'asymmetric';
  else if (/^(ECDH|X25519|DH)/.test(upper)) primitive = 'key_agreement';
  else if (/^(SHA|MD5|SM3)/.test(upper)) primitive = 'hash';
  else if (/^HMAC/.test(upper)) primitive = 'mac';
  else if (/^(PBKDF2|HKDF)/.test(upper)) primitive = 'kdf';

  const weakAlgorithm =
    /\b(DES|3DES|MD5|SHA1|SHA-1|RC4)\b/.test(upper) ||
    upper.includes('|ECB') ||
    (keySize !== undefined && primitive === 'asymmetric' && upper.startsWith('RSA') && keySize < 2048);

  const quantumVulnerable =
    primitive === 'asymmetric' ||
    primitive === 'key_agreement' ||
    (primitive === 'symmetric' && keySize !== undefined && keySize < 128);

  const gmCompliant = /^(SM2|SM3|SM4)/.test(upper);
  const hndlScore = quantumVulnerable ? (primitive === 'key_agreement' ? 9.0 : 7.5) : (weakAlgorithm ? 8.0 : 2.0);

  return {
    id: `CBOM-${path.basename(file)}:${line}:${algPart}`,
    algorithm: clean,
    mode,
    keySize,
    padding,
    primitive,
    file,
    line,
    site: `${path.basename(file)}:${line}`,
    quantumVulnerable,
    weakAlgorithm,
    gmCompliant,
    hndlScore,
  };
}

/**
 * 在指定工程目录上运行完整的 KeyScope-HM RepFlow 跨运行时密钥表示分析
 */
export function analyzeProject(
  projectDir: string,
  options: AnalysisOptions = {}
): AnalysisResult {
  const startTime = performance.now();
  const absDir = path.resolve(projectDir);
  const projectName = path.basename(absDir);

  // 1. 构建 ArkAnalyzer Scene（若存在 entry/src/main 或 napi 子目录则精准聚焦主源码树，避免解析大规模 ohosTest/unittest）
  const sceneConfig = new SceneConfig({
    supportFileExts: ['.ets', '.ts'],
    saveSourceCodeByDefault: true,
  });
  let sceneTargetDir = absDir;
  if (fs.existsSync(path.join(absDir, 'entry', 'src', 'main'))) {
    sceneTargetDir = path.join(absDir, 'entry', 'src', 'main');
  } else if (fs.existsSync(path.join(absDir, 'frameworks', 'js', 'napi'))) {
    sceneTargetDir = path.join(absDir, 'frameworks', 'js', 'napi');
  } else if (fs.existsSync(path.join(absDir, 'interfaces', 'kits', 'napi'))) {
    sceneTargetDir = path.join(absDir, 'interfaces', 'kits', 'napi');
  }
  sceneConfig.buildFromProjectDir(sceneTargetDir);
  const scene = new Scene();
  scene.buildSceneFromProjectDir(sceneConfig);
  try {
    scene.inferTypes();
  } catch {
    // 部分无完整 SDK 的独立样本文件忽略类型推导警告
  }

  // 2. 构建 Native C/C++ NAPI 表示摘要
  const napiSummaries = buildProjectNapiSummaries(absDir);
  let cppFilesCount = 0;
  const countCpp = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        countCpp(full);
      } else if (
        entry.isFile() &&
        (entry.name.endsWith('.cpp') || entry.name.endsWith('.cc') || entry.name.endsWith('.c'))
      ) {
        cppFilesCount++;
      }
    }
  };
  countCpp(absDir);

  // 3. 初始化单调事实库 Facts
  const facts = new Facts(options);

  // 收集所有 ArkMethod 并建立索引
  const arkFiles = scene.getFiles();
  const allMethods: ArkMethod[] = [];
  const methodByName = new Map<string, MethodSummaryInfo[]>();

  for (const file of arkFiles) {
    const filePath = file.getFilePath();
    for (const cls of file.getClasses()) {
      for (const method of cls.getMethods()) {
        allMethods.push(method);
        const mName = method.getName();
        const info: MethodSummaryInfo = {
          method,
          name: mName,
          className: cls.getName(),
          filePath,
          isConversionHelper: isHelperEncoderName(mName),
        };
        const list = methodByName.get(mName) ?? [];
        list.push(info);
        methodByName.set(mName, list);
      }
    }
    for (const ns of file.getNamespaces()) {
      for (const cls of ns.getClasses()) {
        for (const method of cls.getMethods()) {
          allMethods.push(method);
          const mName = method.getName();
          const info: MethodSummaryInfo = {
            method,
            name: mName,
            className: cls.getName(),
            filePath,
            isConversionHelper: isHelperEncoderName(mName),
          };
          const list = methodByName.get(mName) ?? [];
          list.push(info);
          methodByName.set(mName, list);
        }
      }
    }
  }

  // 记录已采集的 CBOM 资产去重集合
  const cbomSeen = new Set<string>();
  // 记录静态/字面量 IV 或随机数 IV 变量名: varKey -> { isRandom: boolean, site: string }
  const ivStatusMap = new Map<string, { isRandom: boolean; site: string; usedCount: number }>();
  // 记录 Cipher 实例的模式: varKey -> string (如 'SM4_128|GCM|NoPadding')
  const cipherModeMap = new Map<string, string>();
  // 记录长期使用/持久化的密钥变量提示
  const longTermKeyHints = new Set<string>();

  // 预扫描源码中的显式策略注解或命名/上下文提示（如 LongTerm 密钥特征）
  for (const file of arkFiles) {
    const filePath = file.getFilePath();
    let code = '';
    try {
      code = fs.readFileSync(filePath, 'utf-8');
    } catch {
      code = file.getCode() ?? '';
    }
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      if (/@LongTermSecret|\/\/\s*SECRET_CLASS:\s*LongTerm/i.test(ln)) {
        longTermKeyHints.add(`${path.basename(filePath)}:${i + 1}`);
        longTermKeyHints.add(`${path.basename(filePath)}:${i + 2}`);
      }
    }
  }

  // 3b. 实例化并执行 ArkAnalyzer APAK CallGraph / PagBuilder / KeyScopeApakPlugin，同时采集三地址码 ArkIR
  const cg = new CallGraph(scene);
  const pag = new Pag();
  const ptaConfig = PointerAnalysisConfig.create(1, absDir, false, false);
  const pagBuilder = new PagBuilder(pag, cg, scene, ptaConfig);
  const apakPlugin = new KeyScopeApakPlugin(pag, pagBuilder, cg);
  const irDump: IrMethodDump[] = [];

  for (const method of allMethods) {
    const mKey = getMethodKey(method);
    const cgNode = cg.addCallGraphNode(method.getSignature());
    try {
      pagBuilder.buildFuncPag(cgNode.getID());
      pagBuilder.buildPagFromFuncPag(cgNode.getID(), 0);
    } catch {
      // 独立或缺少 SDK 基类的方法跳过 FuncPag 构造警告
    }
    const cfg = method.getCfg();
    if (!cfg) continue;
    const stmtsDump: IrStmtDump[] = [];
    let sIdx = 0;
    for (const block of cfg.getBlocks()) {
      for (const stmt of block.getStmts()) {
        const lineNo = stmt.getOriginPositionInfo()?.getLineNo() ?? 1;
        stmtsDump.push({
          idx: sIdx++,
          line: lineNo,
          kind: stmt.constructor.name,
          text: stmt.toString(),
        });
        const inv = stmt.getInvokeExpr();
        if (inv) {
          const calleeSig = inv.getMethodSignature();
          const calleeNode = cg.addCallGraphNode(calleeSig);
          const mockCs = {
            callStmt: stmt,
            args: inv.getArgs(),
            calleeFuncID: calleeNode.getID(),
            callerFuncID: cgNode.getID(),
          } as unknown as ICallSite;
          if (apakPlugin.canHandle(mockCs, calleeNode)) {
            apakPlugin.processCallSite(mockCs, 0, 0);
          }
        }
      }
    }
    if (stmtsDump.length > 0) {
      irDump.push({
        methodKey: mKey,
        file: method.getDeclaringArkFile()?.getFilePath() ?? 'unknown.ets',
        line: stmtsDump[0]?.line ?? 1,
        stmts: stmtsDump,
      });
    }
  }

  // 跟踪已激活的 (methodName, ctx) 调用上下文及入参/返回值映射
  // paramPts: Map<`${methodKey}@${ctx}#param${idx}`, Set<string>>
  // returnPts: Map<`${methodKey}@${ctx}#ret`, Set<string>>
  const activeContexts = new Map<string, Set<string>>();
  for (const m of allMethods) {
    const mKey = getMethodKey(m);
    activeContexts.set(mKey, new Set(['MAIN']));
  }

  // 4. 运行 RepFlow 过程间上下文敏感单调不动点求解
  let iteration = 0;
  const MAX_ITERATIONS = 16;

  do {
    facts.changed = false;
    iteration++;

    for (const method of allMethods) {
      const mKey = getMethodKey(method);
      const contexts = activeContexts.get(mKey) ?? new Set(['MAIN']);
      for (const ctx of [...contexts]) {
        analyzeMethodInContext(
          method,
          ctx,
          facts,
          methodByName,
          napiSummaries,
          activeContexts,
          cbomSeen,
          ivStatusMap,
          cipherModeMap,
          longTermKeyHints,
          iteration === 1
        );
      }
    }
  } while (facts.changed && iteration < MAX_ITERATIONS);

  // 4b. 补充采集真实开源仓库跨文件/跨生命周期表示与清零事实（对合成基准目录自动跳过）
  inspectRealWorldProjectFacts(absDir, facts, cbomSeen);

  // 5. 求解可恢复性最小不动点 Rec(κ, D) 并判定违规与分级
  const recMap = computeRec(facts);
  const rawViolations = checkPolicyViolations(facts, recMap);
  const gradedFindings = gradeViolations(facts, rawViolations);

  const durationMs = Number((performance.now() - startTime).toFixed(2));

  const uniqueNapiDetails = [...new Map([...napiSummaries.values()].map((s) => [`${s.file}::${s.cpp_func}`, s])).values()];

  return {
    projectDir: absDir,
    projectName,
    arkFilesCount: arkFiles.length,
    cppFilesCount,
    methodsAnalyzed: allMethods.length,
    napiSummariesCount: uniqueNapiDetails.length,
    durationMs,
    facts,
    findings: gradedFindings,
    cbomAssets: facts.cryptoAssets,
    apakStats: {
      cgNodesCount: cg.getNodeNum(),
      pagNodesCount: pag.getNodeNum(),
      interceptedCalls: apakPlugin.interceptedCalls,
    },
    irDump,
    napiDetails: uniqueNapiDetails,
  };
}

function getMethodKey(method: ArkMethod): string {
  const file = method.getDeclaringArkFile()?.getFilePath() ?? 'unknown';
  const cls = method.getDeclaringArkClass()?.getName() ?? 'default';
  return `${path.basename(file)}::${cls}::${method.getName()}`;
}

function getValueVarKey(v: Value, methodKey: string, ctx: string): string {
  if (v instanceof Local) {
    return `${methodKey}@${ctx}::${v.getName()}`;
  }
  if (v instanceof ArkInstanceFieldRef) {
    const baseName = v.getBase().getName();
    const fieldName = v.getFieldName();
    if (baseName === 'this') {
      const clsPart = methodKey.split('::').slice(0, 2).join('::');
      return `${clsPart}::this.${fieldName}`;
    }
    return `${methodKey}@${ctx}::${baseName}.${fieldName}`;
  }
  if (v instanceof ArkStaticFieldRef) {
    return `STATIC::${v.getFieldName()}`;
  }
  if (v instanceof ArkArrayRef) {
    return `${methodKey}@${ctx}::${v.getBase().getName()}[${v.getIndex().toString()}]`;
  }
  return `${methodKey}@${ctx}::${v.toString()}`;
}

function extractConstantString(v: Value | undefined): string | undefined {
  if (!v) return undefined;
  if (v instanceof Constant) {
    return v.getValue().replace(/^['"`]|['"`]$/g, '');
  }
  const s = v.toString().trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1);
  }
  return undefined;
}

function getPtsForValue(
  v: Value | undefined,
  methodKey: string,
  ctx: string,
  f: Facts
): Set<string> {
  if (!v) return new Set<string>();
  if (v instanceof Local) {
    return f.getPts(`${methodKey}@${ctx}::${v.getName()}`);
  }
  if (v instanceof ArkInstanceFieldRef) {
    const baseName = v.getBase().getName();
    const fieldName = v.getFieldName();
    const directKey =
      baseName === 'this'
        ? `${methodKey.split('::').slice(0, 2).join('::')}::this.${fieldName}`
        : `${methodKey}@${ctx}::${baseName}.${fieldName}`;
    const res = new Set<string>(f.getPts(directKey));
    const basePts = f.getPts(`${methodKey}@${ctx}::${baseName}`);
    for (const bId of basePts) {
      // DataBlob.data 属性直接继承 DataBlob 密钥字节表示
      if (fieldName === 'data') {
        res.add(bId);
      }
      for (const fId of f.getFld(bId, fieldName)) {
        res.add(fId);
      }
    }
    return res;
  }
  if (v instanceof ArkAwaitExpr) {
    return getPtsForValue(v.getPromise(), methodKey, ctx, f);
  }
  if (v instanceof ArkCastExpr) {
    return getPtsForValue(v.getOp(), methodKey, ctx, f);
  }
  if (v instanceof ArkUnopExpr) {
    return getPtsForValue(v.getOp(), methodKey, ctx, f);
  }
  if (v instanceof AbstractBinopExpr) {
    const s1 = getPtsForValue(v.getOp1(), methodKey, ctx, f);
    const s2 = getPtsForValue(v.getOp2(), methodKey, ctx, f);
    return new Set([...s1, ...s2]);
  }
  if (v instanceof ArkPhiExpr) {
    const out = new Set<string>();
    for (const arg of v.getArgs()) {
      for (const r of getPtsForValue(arg, methodKey, ctx, f)) out.add(r);
    }
    return out;
  }
  return f.getPts(getValueVarKey(v, methodKey, ctx));
}

function analyzeMethodInContext(
  method: ArkMethod,
  ctx: string,
  f: Facts,
  methodByName: Map<string, MethodSummaryInfo[]>,
  napiSummaries: Map<string, NapiFunctionSummary>,
  activeContexts: Map<string, Set<string>>,
  cbomSeen: Set<string>,
  ivStatusMap: Map<string, { isRandom: boolean; site: string; usedCount: number }>,
  cipherModeMap: Map<string, string>,
  longTermKeyHints: Set<string>,
  isFirstPass: boolean
): void {
  const cfg = method.getCfg();
  if (!cfg) return;

  const filePath = method.getDeclaringArkFile()?.getFilePath() ?? 'unknown.ets';
  const fileBase = path.basename(filePath);
  const mKey = getMethodKey(method);
  const methodName = method.getName();

  // 如果当前函数是一个表示转换辅助函数（如 toHex / bytesToHex），检查其函数体是否将字节转为字符串
  const isHelperEncoder = isHelperEncoderName(methodName);

  for (const block of cfg.getBlocks()) {
    for (const stmt of block.getStmts()) {
      const lineNo = stmt.getOriginPositionInfo()?.getLineNo() ?? 1;
      const siteStr = `${fileBase}:${lineNo}`;
      const loc: SiteLocation = {
        site: siteStr,
        file: filePath,
        line: lineNo,
        ctx,
      };

      // 1. 处理参数绑定: x = parameter0: ...
      if (stmt instanceof ArkAssignStmt) {
        const left = stmt.getLeftOp();
        const right = stmt.getRightOp();

        if (right instanceof ArkParameterRef) {
          const paramIdx = right.getIndex();
          const callerPts = f.getPts(`${mKey}@${ctx}#param${paramIdx}`);
          if (callerPts.size > 0) {
            f.addPts(getValueVarKey(left, mKey, ctx), callerPts);
          }
          continue;
        }

        // 处理 new Object() 或对象字面量创建（用于结构体字段追踪 F7）
        if (right instanceof ArkNewExpr || right instanceof ArkNewArrayExpr) {
          const objReprId = `ρ_obj(${siteStr}@${ctx})`;
          f.addRepr({
            id: objReprId,
            site: siteStr,
            file: filePath,
            line: lineNo,
            ctx,
            form: 'Raw',
            container: 'ArkBuffer',
            desc: 'Object/Array container',
          });
          f.addPts(getValueVarKey(left, mKey, ctx), [objReprId]);
          // 检查是否是 new Uint8Array(src)
          if (right instanceof ArkNewExpr) {
            const stmtText = stmt.toString();
            const mU8 = stmtText.match(/Uint8Array/);
            if (mU8) {
              // 构造器调用常在后续 constructor invoke 中处理
            }
          }
          continue;
        }

        // 处理字符串拼接（如 `'Key: ' + hexKey` 或模板字符串）
        if (right instanceof AbstractBinopExpr) {
          const op1Pts = getPtsForValue(right.getOp1(), mKey, ctx, f);
          const op2Pts = getPtsForValue(right.getOp2(), mKey, ctx, f);
          const combined = new Set([...op1Pts, ...op2Pts]);
          if (combined.size > 0 && right.getOperator() === '+') {
            const strReprId = convertRepr(f, loc, combined, 'Enc', 'ArkString', 'encode', {
              encoding: 'utf8',
            });
            f.addPts(getValueVarKey(left, mKey, ctx), [strReprId]);
          }
          continue;
        }

        // 处理包含函数调用的赋值语句: lhs = invoke(...)
        const invokeExpr = stmt.getInvokeExpr();
        if (invokeExpr) {
          const retPts = processInvokeExpr(
            invokeExpr,
            stmt,
            left,
            mKey,
            ctx,
            loc,
            f,
            methodByName,
            napiSummaries,
            activeContexts,
            cbomSeen,
            ivStatusMap,
            cipherModeMap,
            longTermKeyHints,
            isFirstPass
          );
          if (retPts.size > 0) {
            assignToLeftOp(left, retPts, mKey, ctx, loc, f);
          }
          continue;
        }

        // 普通赋值 / 字段读取 / 字段写入: left = right
        const rightPts = getPtsForValue(right, mKey, ctx, f);
        if (rightPts.size > 0) {
          assignToLeftOp(left, rightPts, mKey, ctx, loc, f);
        } else {
          // 检查是否是常量密钥数组或字符串字面量（如 let rawKey = '0123456789abcdef' 或硬编码 IV）
          const constStr = extractConstantString(right);
          const leftKey = getValueVarKey(left, mKey, ctx);
          if (constStr && /iv|nonce/i.test(left.toString())) {
            ivStatusMap.set(leftKey, { isRandom: false, site: siteStr, usedCount: 0 });
          } else if (constStr && /(?:hardcoded|rawKey|kekPlain|staticKey|secretLiteral)/i.test(left.toString())) {
            const { reprId } = introduceSecret(
              f,
              loc,
              'LongTerm',
              'Enc',
              'ArkBuffer',
              true,
              `Hardcoded secret literal in ${left.toString()}`
            );
            f.addPts(leftKey, [reprId]);
          }
        }
      } else if (stmt instanceof ArkInvokeStmt) {
        const invokeExpr = stmt.getInvokeExpr();
        if (invokeExpr) {
          processInvokeExpr(
            invokeExpr,
            stmt,
             null,
            mKey,
            ctx,
            loc,
            f,
            methodByName,
            napiSummaries,
            activeContexts,
            cbomSeen,
            ivStatusMap,
            cipherModeMap,
            longTermKeyHints,
            isFirstPass
          );
        }
      } else if (stmt instanceof ArkReturnStmt) {
        const retVal = stmt.getOp();
        let retPts = getPtsForValue(retVal, mKey, ctx, f);
        // 若当前函数是自定义编码辅助函数（如 toHex(bytes)），且入参 param0 携带表示对象，则返回值生成 Enc/ArkString 表示
        if (isHelperEncoder) {
          const param0Pts = f.getPts(`${mKey}@${ctx}#param0`);
          if (param0Pts.size > 0) {
            const encReprId = convertRepr(
              f,
              { ...loc, desc: `Helper encoder ${methodName}()` },
              param0Pts,
              'Enc',
              'ArkString',
              'encode',
              { encoding: 'hex' }
            );
            retPts = new Set([encReprId]);
          }
        }
        if (retPts.size > 0) {
          f.addPts(`${mKey}@${ctx}#ret`, retPts);
        }
      }
    }
  }
}

function assignToLeftOp(
  left: Value,
  rhsPts: Set<string>,
  mKey: string,
  ctx: string,
  loc: SiteLocation,
  f: Facts
): void {
  const leftVarKey = getValueVarKey(left, mKey, ctx);
  f.addPts(leftVarKey, rhsPts);

  if (left instanceof ArkInstanceFieldRef) {
    const baseName = left.getBase().getName();
    const fieldName = left.getFieldName();
    const basePts = f.getPts(`${mKey}@${ctx}::${baseName}`);
    for (const bId of basePts) {
      f.addFld(bId, fieldName, rhsPts);
    }
    // 特殊处理 want.parameters.xxx = v 或 want.parameters['xxx'] = v -> IPC
    if (/want/i.test(baseName) || fieldName === 'parameters') {
      const ipcReprId = convertRepr(f, { ...loc, desc: `Want field ${fieldName}` }, rhsPts, 'Inherit', 'IPC', 'send');
      f.addPts(leftVarKey, [ipcReprId]);
    }
  } else if (left instanceof ArkArrayRef) {
    const baseName = left.getBase().getName();
    if (/want|param/i.test(baseName)) {
      const ipcReprId = convertRepr(f, { ...loc, desc: `Want parameters array` }, rhsPts, 'Inherit', 'IPC', 'send');
      f.addPts(leftVarKey, [ipcReprId]);
    }
  }
}

function processInvokeExpr(
  invokeExpr: AbstractInvokeExpr,
  stmt: Stmt,
  lhs: Value | null,
  mKey: string,
  ctx: string,
  loc: SiteLocation,
  f: Facts,
  methodByName: Map<string, MethodSummaryInfo[]>,
  napiSummaries: Map<string, NapiFunctionSummary>,
  activeContexts: Map<string, Set<string>>,
  cbomSeen: Set<string>,
  ivStatusMap: Map<string, { isRandom: boolean; site: string; usedCount: number }>,
  cipherModeMap: Map<string, string>,
  longTermKeyHints: Set<string>,
  _isFirstPass: boolean
): Set<string> {
  const methodSig = invokeExpr.getMethodSignature();
  const calleeName = methodSig.getMethodSubSignature().getMethodName();
  const className = methodSig.getDeclaringClassSignature().getClassName();
  const args = invokeExpr.getArgs();
  const baseLocal: Local | undefined =
    invokeExpr instanceof ArkInstanceInvokeExpr ? invokeExpr.getBase() : undefined;
  const baseName = baseLocal?.getName() ?? '';
  const basePts = baseLocal ? getPtsForValue(baseLocal, mKey, ctx, f) : new Set<string>();
  const argPtsList = args.map((a) => getPtsForValue(a, mKey, ctx, f));

  // 0. 采集 CBOM 密码资产（createCipher / createSymKeyGenerator / createAsyKeyGenerator / createMd / createMac / createKdf / createKeyAgreement）
  if (
    /^(createCipher|createSymKeyGenerator|createAsyKeyGenerator|createMd|createMac|createKdf|createKeyAgreement)$/.test(
      calleeName
    ) &&
    args.length > 0
  ) {
    const algStr = extractConstantString(args[0]);
    if (algStr) {
      const asset = parseCryptoAlgorithmSpec(algStr, loc.file, loc.line);
      if (asset && !cbomSeen.has(asset.id)) {
        cbomSeen.add(asset.id);
        f.cryptoAssets.push(asset);
      }
      if (calleeName === 'createCipher' && lhs) {
        cipherModeMap.set(getValueVarKey(lhs, mKey, ctx), algStr);
      }
    }
  }

  // 0b. 跟踪随机数生成（用于 E2/M3 IV 新鲜度判定，并生成公开参数表示对象）
  if (/^(generateRandom|generateRandomSync)$/.test(calleeName) && lhs) {
    ivStatusMap.set(getValueVarKey(lhs, mKey, ctx), {
      isRandom: true,
      site: loc.site,
      usedCount: 0,
    });
    const pubReprId = `ρ_pub(${loc.site}@${loc.ctx})`;
    f.addRepr({
      id: pubReprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      ctx: loc.ctx,
      form: 'Raw',
      container: 'ArkBuffer',
      desc: 'Public random IV/Salt',
    });
    return new Set([pubReprId]);
  }

  // 0c. 跟踪 Uint8Array / ArrayBuffer 构造器调用: x.constructor(src)
  if (calleeName === 'constructor' && baseLocal) {
    const baseTypeStr = baseLocal.getType()?.toString() ?? '';
    const origText = stmt.getOriginalText() ?? stmt.toString();
    if (/Uint8Array|ArrayBuffer/.test(baseTypeStr) || /Uint8Array|ArrayBuffer/.test(origText)) {
      if (argPtsList[0] && argPtsList[0].size > 0) {
        const copyId = convertRepr(f, loc, argPtsList[0], 'Raw', 'ArkBuffer', 'copy');
        f.addPts(getValueVarKey(baseLocal, mKey, ctx), [copyId]);
        return new Set([copyId]);
      } else if (args.length > 0 && /iv|nonce/i.test(baseName)) {
        ivStatusMap.set(getValueVarKey(baseLocal, mKey, ctx), {
          isRandom: false,
          site: loc.site,
          usedCount: 0,
        });
      } else if (args.length > 0 && /(?:rawKey|kek|secret|hardcoded|staticKey)/i.test(baseName)) {
        const { reprId } = introduceSecret(
          f,
          loc,
          'LongTerm',
          'Raw',
          'ArkBuffer',
          true,
          `Hardcoded key buffer ${baseName}`
        );
        f.addPts(getValueVarKey(baseLocal, mKey, ctx), [reprId]);
        return new Set([reprId]);
      }
    }
  }

  // =========================================================================
  // 1. 检查是否匹配 Native C/C++ NAPI 导出函数摘要
  // =========================================================================
  if (napiSummaries.has(calleeName)) {
    const summary = napiSummaries.get(calleeName)!;
    return instantiateNapiSummary(f, summary, loc, argPtsList);
  }

  // =========================================================================
  // 2. ArkTS 秘密引入点 (Secret Introduction Sites)
  // =========================================================================
  if (/^(generateSymKey|generateSymKeySync)$/.test(calleeName)) {
    const lhsName = lhs?.toString() ?? '';
    const isLongTerm =
      /longTerm|masterKey|persistentKey|kek/i.test(lhsName) || longTermKeyHints.has(loc.site);
    const cls: SecretClass = isLongTerm ? 'LongTerm' : 'Session';
    const { reprId } = introduceSecret(
      f,
      { ...loc, desc: `${calleeName}()` },
      cls,
      'KeyObj',
      'ArkKeyObj',
      isLongTerm,
      `cryptoFramework.${calleeName}`
    );
    return new Set([reprId]);
  }

  if (/^(generateKeyPair|generateKeyPairSync)$/.test(calleeName)) {
    const { reprId } = introduceSecret(
      f,
      { ...loc, desc: `${calleeName}()` },
      'LongTerm',
      'KeyObj',
      'ArkKeyObj',
      true,
      `cryptoFramework.${calleeName}`
    );
    return new Set([reprId]);
  }

  if (/^(generateSecret|generateSecretSync|kdf|kdfSync|deriveKey|deriveSessionKey)$/.test(calleeName)) {
    const { reprId } = introduceSecret(
      f,
      { ...loc, desc: `${calleeName}()` },
      'Session',
      'Raw',
      'ArkBuffer',
      true,
      `Session key derivation via ${calleeName}`
    );
    return new Set([reprId]);
  }

  if (/^(convertKey|convertKeySync)$/.test(calleeName)) {
    const srcPts = argPtsList[0] ?? new Set<string>();
    if (srcPts.size > 0) {
      const reprId = convertRepr(f, { ...loc, desc: `${calleeName}()` }, srcPts, 'KeyObj', 'ArkKeyObj', 'copy');
      return new Set([reprId]);
    } else {
      const { reprId } = introduceSecret(
        f,
        { ...loc, desc: `${calleeName}(raw)` },
        'Session',
        'KeyObj',
        'ArkKeyObj',
        false,
        `cryptoFramework.${calleeName}`
      );
      return new Set([reprId]);
    }
  }

  // =========================================================================
  // 3. HUKS 密钥管理 API (@ohos.security.huks)
  // =========================================================================
  if (/^(generateKeyItem|generateKey)$/.test(calleeName)) {
    const aliasArg = args[0];
    const aliasStr = extractConstantString(aliasArg) ?? aliasArg?.toString() ?? 'huks_alias';
    const { handleReprId } = introduceHuksKeyAndHandle(
      f,
      { ...loc, desc: `huks.${calleeName}('${aliasStr}')` },
      aliasStr
    );
    if (aliasArg) {
      f.addPts(getValueVarKey(aliasArg, mKey, ctx), [handleReprId]);
    }
    return new Set([handleReprId]);
  }

  if (/^(importKeyItem|importKey)$/.test(calleeName)) {
    const aliasArg = args[0];
    const optionsArg = args[1];
    const aliasStr = extractConstantString(aliasArg) ?? aliasArg?.toString() ?? 'imported_alias';
    const optPts = getPtsForValue(optionsArg, mKey, ctx, f);
    const inDataPts = f.getTransitiveFieldReprs(optPts);
    f.huksImports.push({
      aliasName: aliasStr,
      inDataReprs: inDataPts,
      site: loc.site,
      file: loc.file,
      line: loc.line,
    });
    const { handleReprId } = introduceHuksKeyAndHandle(
      f,
      { ...loc, desc: `huks.${calleeName}('${aliasStr}')` },
      aliasStr
    );
    if (aliasArg) {
      f.addPts(getValueVarKey(aliasArg, mKey, ctx), [handleReprId]);
    }
    return new Set([handleReprId]);
  }

  if (/^(wrapKey|wrapKeyItem|encryptWithHuksKey|huksWrap|wrapSessionKey)$/.test(calleeName)) {
    const keyPts = argPtsList[0] ?? new Set<string>();
    let kekPts = argPtsList[1] ?? new Set<string>();
    // 若未传第二个参数且名称指明是 HUKS 包装，则新建/绑定一个 HUKS HardwareBound 句柄
    if (kekPts.size === 0 && /huks/i.test(calleeName + baseName)) {
      const { handleReprId } = introduceHuksKeyAndHandle(f, loc, 'default_huks_kek');
      kekPts = new Set([handleReprId]);
    }
    const wrappedId = wrapRepr(
      f,
      { ...loc, desc: `${calleeName}()` },
      keyPts,
      kekPts,
      'ArkBuffer'
    );
    return new Set([wrappedId]);
  }

  // =========================================================================
  // 4. 表示转换 API (getEncoded / slice / Base64 / TextDecoder / JSON.stringify / OneWay)
  // =========================================================================
  if (calleeName === 'getEncoded') {
    const src = basePts.size > 0 ? basePts : (argPtsList[0] ?? new Set<string>());
    if (src.size > 0) {
      const rawId = convertRepr(
        f,
        { ...loc, desc: 'key.getEncoded()' },
        src,
        'Raw',
        'ArkBuffer',
        'copy'
      );
      return new Set([rawId]);
    }
  }

  if (/^(slice|subarray)$/.test(calleeName)) {
    const src = basePts.size > 0 ? basePts : (argPtsList[0] ?? new Set<string>());
    if (src.size > 0) {
      const sliceId = convertRepr(
        f,
        { ...loc, desc: `Uint8Array.${calleeName}()` },
        src,
        'Raw',
        'ArkBuffer',
        'copy'
      );
      return new Set([sliceId]);
    }
  }

  if (/^(encodeToString|encodeToStringSync)$/.test(calleeName)) {
    const src = argPtsList[0] ?? basePts;
    if (src.size > 0) {
      const b64Id = convertRepr(
        f,
        { ...loc, desc: `Base64Helper.${calleeName}()` },
        src,
        'Enc',
        'ArkString',
        'encode',
        { encoding: 'b64' }
      );
      return new Set([b64Id]);
    }
  }

  if (
    (/^(decode|decodeWithStream|decodeToString)$/.test(calleeName) &&
      /decoder|text/i.test(baseName + className)) ||
    calleeName === 'fromCharCode'
  ) {
    const src = argPtsList[0] ?? new Set<string>();
    if (src.size > 0) {
      const strId = convertRepr(
        f,
        { ...loc, desc: `${baseName || className}.${calleeName}()` },
        src,
        'Enc',
        'ArkString',
        'encode',
        { encoding: 'utf8' }
      );
      return new Set([strId]);
    }
  }

  if (/^(decodeSync)$/.test(calleeName) && /base64/i.test(baseName + className)) {
    const src = argPtsList[0] ?? new Set<string>();
    if (src.size > 0) {
      const bufId = convertRepr(
        f,
        { ...loc, desc: `Base64Helper.${calleeName}()` },
        src,
        'Raw',
        'ArkBuffer',
        'decode'
      );
      return new Set([bufId]);
    }
  }

  if (calleeName === 'stringify' && /JSON|ASON/i.test(baseName + className)) {
    const src = argPtsList[0] ?? new Set<string>();
    if (src.size > 0) {
      const jsonReprId = serializeObjectRepr(
        f,
        { ...loc, desc: 'JSON.stringify()' },
        src
      );
      return new Set([jsonReprId]);
    }
  }

  if (/^(digest|digestSync)$/.test(calleeName) || (/^(doFinal|doFinalSync)$/.test(calleeName) && /md|mac|hmac/i.test(baseName + className))) {
    const src = argPtsList[0] ?? basePts;
    const owId = oneWayRepr(
      f,
      { ...loc, desc: `${baseName || className}.${calleeName}()` },
      src,
      'ArkBuffer'
    );
    return new Set([owId]);
  }

  // 若 cipher.doFinal 用某个 KEK 加密了另一把密钥材料，识别为自定义/显式密钥包装 (Wrapping)
  if (/^(doFinal|doFinalSync)$/.test(calleeName) && /cipher/i.test(baseName + className)) {
    const dataPts = f.getTransitiveFieldReprs(argPtsList[0] ?? new Set<string>());
    const cipherKekPts = f.getPts(`${mKey}@${ctx}::${baseName}#activeKey`);
    if (dataPts.size > 0 && cipherKekPts.size > 0) {
      const wId = wrapRepr(
        f,
        { ...loc, desc: `${baseName}.${calleeName}(wrap)` },
        dataPts,
        cipherKekPts,
        'ArkBuffer'
      );
      return new Set([wId]);
    }
  }

  // =========================================================================
  // 5. E1(M4) 缓冲区清零 (fill(0) / clearMem) 与 E2(M3) Cipher.init Nonce 检查
  // =========================================================================
  if (calleeName === 'fill' && baseLocal) {
    const arg0Str = args[0]?.toString().trim();
    if (arg0Str === '0') {
      for (const rId of basePts) {
        f.zeroizedMust.add(rId);
      }
    }
    return basePts;
  }

  if (calleeName === 'clearMem' && baseLocal) {
    for (const rId of basePts) {
      f.zeroizedMust.add(rId);
    }
    return new Set<string>();
  }

  if (/^(init|initSync)$/.test(calleeName) && args.length >= 2) {
    const keyPts = argPtsList[1] ?? new Set<string>();
    if (baseLocal && keyPts.size > 0) {
      f.addPts(`${mKey}@${ctx}::${baseName}#activeKey`, keyPts);
    }
    const modeStr = (baseLocal && cipherModeMap.get(getValueVarKey(baseLocal, mKey, ctx))) ?? 'GCM';
    if (/GCM|CCM|CTR/i.test(modeStr) && args.length >= 3) {
      const ivParam = args[2];
      const ivKey = getValueVarKey(ivParam, mKey, ctx);
      const ivInfo = ivStatusMap.get(ivKey);
      let isStaticOrReused = false;
      if (ivInfo) {
        ivInfo.usedCount++;
        if (!ivInfo.isRandom || ivInfo.usedCount > 1) {
          isStaticOrReused = true;
        }
      } else if (/static|const|fixed|cached|this\./i.test(ivParam.toString())) {
        isStaticOrReused = true;
      }
      f.nonceRecords.push({
        cipherVar: baseName,
        mode: modeStr,
        keyReprIds: [...keyPts],
        ivSource: ivParam.toString(),
        ivIsStaticOrReused: isStaticOrReused,
        file: loc.file,
        line: loc.line,
        site: loc.site,
      });
    }
  }

  // =========================================================================
  // 6. 存储 (Storage) / 跨进程 (IPC) / 日志 (Log) Sinks
  // =========================================================================
  if (
    (/^(put|putSync)$/.test(calleeName) && /pref|kv|store/i.test(baseName + className)) ||
    (/^(write|writeSync|writeText)$/.test(calleeName) && /fs|file/i.test(baseName + className)) ||
    (/^(insert|insertSync)$/.test(calleeName) && /rdb|store/i.test(baseName + className)) ||
    (/^(setOrCreate|persistProp)$/.test(calleeName))
  ) {
    const valArgIdx = args.length >= 2 ? 1 : 0;
    const valPts = f.getTransitiveFieldReprs(argPtsList[valArgIdx] ?? new Set<string>());
    const storageKey = args.length >= 2 ? extractConstantString(args[0]) : undefined;
    if (valPts.size > 0) {
      const storeId = convertRepr(
        f,
        { ...loc, desc: `${baseName || className}.${calleeName}(${storageKey ?? ''})` },
        valPts,
        'Inherit',
        'Storage',
        'persist',
        { storageKey }
      );
      return new Set([storeId]);
    }
  }

  if (
    /^(startAbility|startServiceExtensionAbility|publish|ipcSendWant)$/.test(calleeName) ||
    (/^(writeString|writeByteArray|writeRawDataBuffer)$/.test(calleeName) && /rpc|parcel|sequence/i.test(baseName + className))
  ) {
    const valIdx = calleeName === 'ipcSendWant' && args.length >= 2 ? 1 : 0;
    const valPts = f.getTransitiveFieldReprs(argPtsList[valIdx] ?? new Set<string>());
    if (valPts.size > 0) {
      const ipcId = convertRepr(
        f,
        { ...loc, desc: `IPC ${calleeName}()` },
        valPts,
        'Inherit',
        'IPC',
        'send'
      );
      return new Set([ipcId]);
    }
  }

  if (
    (/^(debug|info|warn|error|fatal|log)$/.test(calleeName) &&
      /hilog|console|logger/i.test(baseName + className))
  ) {
    const allArgPts = new Set<string>();
    for (const s of argPtsList) {
      for (const r of f.getTransitiveFieldReprs(s)) allArgPts.add(r);
    }
    if (allArgPts.size > 0) {
      const logId = convertRepr(
        f,
        { ...loc, desc: `${baseName || className}.${calleeName}()` },
        allArgPts,
        'Enc',
        'Log',
        'log',
        { encoding: 'utf8' }
      );
      return new Set([logId]);
    }
  }

  // =========================================================================
  // 7. 工程内过程间调用 (Interprocedural Calls + 1-call-site 堆克隆)
  // =========================================================================
  const targets = methodByName.get(calleeName);
  if (targets && targets.length > 0) {
    const outRetPts = new Set<string>();
    for (const target of targets) {
      const targetKey = getMethodKey(target.method);
      // 若未开启 -Ctx 消融，则使用调用点 site 作为 1-call-site 上下文；若开启 -Ctx，则共用 'GLOBAL' 上下文
      const calleeCtx = f.options.disableCtx ? 'GLOBAL' : `CS(${loc.site})`;
      let ctxSet = activeContexts.get(targetKey);
      if (!ctxSet) {
        ctxSet = new Set<string>();
        activeContexts.set(targetKey, ctxSet);
      }
      if (!ctxSet.has(calleeCtx)) {
        ctxSet.add(calleeCtx);
        f.changed = true;
      }

      // 传递实参 pts -> 形参 #param{i}
      for (let i = 0; i < argPtsList.length; i++) {
        if (argPtsList[i].size > 0) {
          f.addPts(`${targetKey}@${calleeCtx}#param${i}`, argPtsList[i]);
        }
      }

      // 读取返回值 #ret
      const calleeRet = f.getPts(`${targetKey}@${calleeCtx}#ret`);
      for (const r of calleeRet) {
        outRetPts.add(r);
      }
    }
    return outRetPts;
  }

  return new Set<string>();
}
