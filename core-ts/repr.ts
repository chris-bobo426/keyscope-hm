/**
 * core-ts/repr.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— LSR (Logical-Secret / Representation) 形式化模型与单调事实库
 *
 * 核心设计原则：
 * 1. 逻辑秘密 κ ∈ K 与物理表示对象 ρ ∈ R 解耦；
 * 2. 每个表示对象 ρ 的 form 与 container 在创建点固定不变，不在控制流汇合点做逐维属性合并；
 * 3. 控制流汇合只对指向集合 pts(v, c) ⊆ H 取并集，从结构上避免身份丢失与不可能状态组合；
 * 4. 所有关系 (pts, fld, carries, wrapBy, handleOf, prov) 在求解过程中单调增长。
 */

export type Form = 'Raw' | 'Enc' | 'KeyObj' | 'Handle' | 'Wrapped' | 'OneWay';
export type EncodingKind = 'hex' | 'b64' | 'utf8' | 'latin1' | 'utf16' | 'json' | 'none';
export type Container =
  | 'NativeHeap'
  | 'ArkBuffer'
  | 'ArkString'
  | 'ArkKeyObj'
  | 'Storage'
  | 'IPC'
  | 'Log'
  | 'HUKS';

export type Domain = 'D_mem' | 'D_store' | 'D_ipc' | 'D_log' | 'D_safe';
export type SecretClass = 'Session' | 'LongTerm' | 'HardwareBound';
export type Op =
  | 'copy'
  | 'alias'
  | 'encode'
  | 'decode'
  | 'wrap'
  | 'unwrap'
  | 'persist'
  | 'send'
  | 'log'
  | 'napi'
  | 'derive'
  | 'field_store'
  | 'field_load';

export type ConfidenceGrade = 'High' | 'Medium' | 'Uncertain';

export const FORM_RECOVERABILITY_RANK: Record<Form, number> = {
  OneWay: 0,
  Handle: 1,
  Wrapped: 2,
  KeyObj: 3,
  Raw: 4,
  Enc: 5,
};

export function joinForm(a: Form, b: Form): Form {
  return FORM_RECOVERABILITY_RANK[b] > FORM_RECOVERABILITY_RANK[a] ? b : a;
}

export interface Secret {
  id: string;
  site: string;
  file: string;
  line: number;
  cls: SecretClass;
  clsFromUser: boolean;
  unambiguousIntro: boolean;
  originDesc: string;
  algorithm?: string;
}

export interface Repr {
  id: string;
  site: string;
  file: string;
  line: number;
  ctx: string;
  readonly form: Form;
  readonly encoding?: EncodingKind;
  readonly container: Container;
  readonly isSharedMemory?: boolean;
  readonly implicitIpc?: boolean;
  readonly uncertain?: boolean;
  readonly storageKey?: string;
  readonly desc?: string;
}

export interface ProvenanceEdge {
  from: string;
  op: Op;
  to: string;
  site: string;
  file: string;
  line: number;
  detail?: string;
}

export interface CryptoAssetItem {
  id: string;
  algorithm: string;
  mode?: string;
  keySize?: number;
  padding?: string;
  primitive: 'symmetric' | 'asymmetric' | 'hash' | 'mac' | 'kdf' | 'key_agreement' | 'rng';
  file: string;
  line: number;
  site: string;
  quantumVulnerable: boolean;
  weakAlgorithm: boolean;
  gmCompliant: boolean;
  hndlScore: number;
}

export interface NonceInitRecord {
  cipherVar: string;
  mode: string;
  keyReprIds: string[];
  ivSource: string;
  ivIsStaticOrReused: boolean;
  file: string;
  line: number;
  site: string;
}

export interface PolicyConfig {
  /** 按文件:行号 或 变量名/函数名 显式指定逻辑秘密类别 */
  secretClasses?: Record<string, SecretClass>;
  /** 自定义辅助函数或包装函数注解 */
  customWrappers?: string[];
  customEncoders?: string[];
}

export interface AnalysisOptions {
  /** 消融实验开关：去掉 κ 身份区分（所有秘密退化为单一匿名标签 κ_ANON） */
  disableIdentity?: boolean;
  /** 消融实验开关：不区分 NAPI 拷贝与别名（统一视作拷贝或别名） */
  disableCopyAlias?: boolean;
  /** 消融实验开关：关闭表示转换辅助函数的 1-call-site 堆克隆（上下文不敏感） */
  disableCtx?: boolean;
  /** 消融实验开关：不做包装密钥可恢复性递归不动点（Wrapped 一律视为安全） */
  disableRec?: boolean;
  /** 消融实验开关：不建句柄模型（HUKS 别名字符串视作携带秘密的字符串） */
  disableHandle?: boolean;
  /** 是否启用 E1(清零/M4)、E2(Nonce复用/M3)、E3(导入前暴露/M2)、M6(CBOM) 扩展检测 */
  enableExtensions?: boolean;
  /** 外部策略覆盖配置 */
  policy?: PolicyConfig;
}

/**
 * 将容器 Container 映射到攻击域 Domain
 */
export function domOf(c: Container): Domain {
  switch (c) {
    case 'ArkString':
      return 'D_mem'; // 托管不可变字符串，不可按需清零，驻留于托管堆内存域
    case 'Storage':
      return 'D_store'; // 持久化存储域
    case 'IPC':
      return 'D_ipc'; // 跨进程通信域
    case 'Log':
      return 'D_log'; // 系统/控制台日志域
    default:
      return 'D_safe'; // NativeHeap / ArkBuffer / ArkKeyObj / HUKS：可受控清零或由安全环境隔离
  }
}

/**
 * 单调事实库 Facts：所有集合关系只增不删，确保在有限域上必然收敛至最小不动点
 */
export class Facts {
  readonly options: AnalysisOptions;

  /** K: 逻辑秘密集合 κ_id -> Secret */
  secrets = new Map<string, Secret>();
  /** R: 物理表示对象集合 ρ_id -> Repr */
  reprs = new Map<string, Repr>();

  /** pts(v, c) ⊆ R: 变量(含上下文)指向的表示对象集合 */
  pts = new Map<string, Set<string>>();
  /** fld(h, f) ⊆ R: 抽象对象字段指向的表示对象集合 (key = `${reprId}.${fieldName}`) */
  fld = new Map<string, Set<string>>();

  /** carries(ρ) ⊆ K: 表示对象 ρ 承载的逻辑秘密集合 */
  carries = new Map<string, Set<string>>();
  /** directCarries(ρ) ⊆ K: 表示对象 ρ 以未加密保护形态 (Raw/Enc/KeyObj) 直接承载的逻辑秘密集合 */
  directCarries = new Map<string, Set<string>>();
  /** wrapBy(ρ) ⊆ K: 对 Wrapped 表示对象，记录加密包装它的 KEK 所承载的逻辑秘密集合 */
  wrapBy = new Map<string, Set<string>>();
  /** handleOf(ρ) ⊆ K: 对 Handle 表示对象，记录其引用的 HUKS 逻辑秘密集合 */
  handleOf = new Map<string, Set<string>>();

  /** Prov ⊆ R × Op × R: 表示溯源图边列表 */
  prov: ProvenanceEdge[] = [];
  private provKeySet = new Set<string>();

  /** E1 (M4) 清零跟踪：记录已被安全清零的表示对象 ID 集合（别名共享同一底层表示 ID） */
  zeroizedMust = new Set<string>();
  /** E1 (M4) 普通可被编译器优化的 memset 记录 */
  plainMemset = new Set<string>();
  /** 存在未清零异常返回分支的表示对象 ID */
  partialPathUnzeroized = new Set<string>();

  /** E2 (M3) GCM/CTR Nonce 初始化记录 */
  nonceRecords: NonceInitRecord[] = [];
  /** E3 (M2) HUKS 明文导入点记录: [{ aliasRepr, inDataReprs, site, file, line }] */
  huksImports: Array<{
    aliasName: string;
    inDataReprs: Set<string>;
    site: string;
    file: string;
    line: number;
  }> = [];

  /** M6 密码资产清单 (CBOM) */
  cryptoAssets: CryptoAssetItem[] = [];

  /** 本轮迭代是否有新事实加入 */
  changed = false;

  constructor(options: AnalysisOptions = {}) {
    this.options = options;
  }

  private addToMapSet(m: Map<string, Set<string>>, k: string, vs: Iterable<string>): boolean {
    let s = m.get(k);
    if (!s) {
      s = new Set<string>();
      m.set(k, s);
    }
    const before = s.size;
    for (const v of vs) {
      s.add(v);
    }
    if (s.size !== before) {
      this.changed = true;
      return true;
    }
    return false;
  }

  normalizeSecretId(rawId: string): string {
    if (this.options.disableIdentity) {
      return 'κ_ANON';
    }
    return rawId;
  }

  addSecret(secret: Secret): Secret {
    const id = this.normalizeSecretId(secret.id);
    const existing = this.secrets.get(id);
    if (!existing) {
      const normSecret: Secret = { ...secret, id };
      // 检查是否有外部 policy.json 覆盖
      if (this.options.policy?.secretClasses) {
        const override =
          this.options.policy.secretClasses[secret.id] ??
          this.options.policy.secretClasses[secret.site];
        if (override) {
          normSecret.cls = override;
          normSecret.clsFromUser = true;
        }
      }
      this.secrets.set(id, normSecret);
      this.changed = true;
      return normSecret;
    }
    return existing;
  }

  addRepr(repr: Repr): Repr {
    const existing = this.reprs.get(repr.id);
    if (!existing) {
      this.reprs.set(repr.id, repr);
      this.changed = true;
      return repr;
    }
    const mergedForm = joinForm(existing.form, repr.form);
    const mergedEncoding =
      mergedForm === repr.form
        ? (repr.encoding ?? existing.encoding)
        : (existing.encoding ?? repr.encoding);
    const mergedUncertain = Boolean(existing.uncertain || repr.uncertain);
    const mergedImplicitIpc = Boolean(existing.implicitIpc || repr.implicitIpc);
    const mergedStorageKey = existing.storageKey ?? repr.storageKey;
    if (
      mergedForm !== existing.form ||
      mergedEncoding !== existing.encoding ||
      mergedUncertain !== Boolean(existing.uncertain) ||
      mergedImplicitIpc !== Boolean(existing.implicitIpc) ||
      mergedStorageKey !== existing.storageKey
    ) {
      const updated: Repr = {
        ...existing,
        form: mergedForm,
        encoding: mergedEncoding,
        uncertain: mergedUncertain,
        implicitIpc: mergedImplicitIpc,
        storageKey: mergedStorageKey,
      };
      this.reprs.set(repr.id, updated);
      this.changed = true;
      return updated;
    }
    return existing;
  }

  addPts(varKey: string, reprIds: Iterable<string>): boolean {
    return this.addToMapSet(this.pts, varKey, reprIds);
  }

  getPts(varKey: string): Set<string> {
    return this.pts.get(varKey) ?? new Set<string>();
  }

  addFld(baseReprId: string, fieldName: string, reprIds: Iterable<string>): boolean {
    return this.addToMapSet(this.fld, `${baseReprId}.${fieldName}`, reprIds);
  }

  getFld(baseReprId: string, fieldName: string): Set<string> {
    return this.fld.get(`${baseReprId}.${fieldName}`) ?? new Set<string>();
  }

  /**
   * 获取某个表示对象及其所有字段递归指向的表示对象集合（用于 JSON.stringify 等结构体序列化）
   */
  getTransitiveFieldReprs(rootReprIds: Iterable<string>): Set<string> {
    const visited = new Set<string>();
    const queue = [...rootReprIds];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);
      for (const [k, targets] of this.fld.entries()) {
        if (k.startsWith(`${curr}.`)) {
          for (const t of targets) {
            if (!visited.has(t)) queue.push(t);
          }
        }
      }
    }
    return visited;
  }

  addCarries(reprId: string, secretIds: Iterable<string>): boolean {
    const normalized = [...secretIds].map((k) => this.normalizeSecretId(k));
    return this.addToMapSet(this.carries, reprId, normalized);
  }

  getCarries(reprId: string): Set<string> {
    return this.carries.get(reprId) ?? new Set<string>();
  }

  addDirectCarries(reprId: string, secretIds: Iterable<string>): boolean {
    const normalized = [...secretIds].map((k) => this.normalizeSecretId(k));
    return this.addToMapSet(this.directCarries, reprId, normalized);
  }

  getDirectCarries(reprId: string): Set<string> {
    return this.directCarries.get(reprId) ?? new Set<string>();
  }

  addWrapBy(reprId: string, secretIds: Iterable<string>): boolean {
    const normalized = [...secretIds].map((k) => this.normalizeSecretId(k));
    return this.addToMapSet(this.wrapBy, reprId, normalized);
  }

  getWrapBy(reprId: string): Set<string> {
    return this.wrapBy.get(reprId) ?? new Set<string>();
  }

  addHandle(reprId: string, secretIds: Iterable<string>): boolean {
    const normalized = [...secretIds].map((k) => this.normalizeSecretId(k));
    return this.addToMapSet(this.handleOf, reprId, normalized);
  }

  getHandle(reprId: string): Set<string> {
    return this.handleOf.get(reprId) ?? new Set<string>();
  }

  addProv(edge: ProvenanceEdge): void {
    const key = `${edge.from}|${edge.op}|${edge.to}|${edge.site}`;
    if (!this.provKeySet.has(key)) {
      this.provKeySet.add(key);
      this.prov.push(edge);
      this.changed = true;
    }
  }
}
