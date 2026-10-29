/**
 * core-ts/rules/transfer.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 表示对象创建、拷贝、别名、编码、包装与单向派生转移规则
 */

import {
  Facts,
  Form,
  EncodingKind,
  Container,
  Op,
  SecretClass,
  Repr,
  joinForm,
} from '../repr';

export interface SiteLocation {
  site: string;
  file: string;
  line: number;
  ctx: string;
  desc?: string;
}

/**
 * 1. 秘密引入点：新建逻辑秘密 κ_s 与初始表示对象 ρ_s
 * 例如：generateSymKey(), ECDH/HKDF 派生, Native RAND_bytes
 */
export function introduceSecret(
  f: Facts,
  loc: SiteLocation,
  cls: SecretClass,
  form: Form,
  container: Container,
  unambiguousIntro: boolean,
  originDesc: string,
  algorithm?: string
): { secretId: string; reprId: string } {
  const rawSecretId = `κ(${loc.site})`;
  const secret = f.addSecret({
    id: rawSecretId,
    site: loc.site,
    file: loc.file,
    line: loc.line,
    cls,
    clsFromUser: false,
    unambiguousIntro,
    originDesc,
    algorithm,
  });

  const reprId = `ρ(${loc.site}@${loc.ctx})`;
  f.addRepr({
    id: reprId,
    site: loc.site,
    file: loc.file,
    line: loc.line,
    ctx: loc.ctx,
    form,
    container,
    desc: loc.desc ?? originDesc,
  });
  f.addCarries(reprId, [secret.id]);
  if (form === 'Raw' || form === 'Enc' || form === 'KeyObj') {
    f.addDirectCarries(reprId, [secret.id]);
  }
  return { secretId: secret.id, reprId };
}

/**
 * 2. HUKS 密钥生成与句柄绑定：
 * 新建 HardwareBound 逻辑秘密 κ_h（位于 HUKS 内部），并将别名表示对象标记为 Handle
 * 若消融开关 disableHandle 开启，则将别名错误地视作携带秘密的 Enc 字符串（用于验证 -Handle 消融）
 */
export function introduceHuksKeyAndHandle(
  f: Facts,
  loc: SiteLocation,
  aliasStrValue: string
): { secretId: string; handleReprId: string } {
  const rawSecretId = `κ_huks(${aliasStrValue}@${loc.site})`;
  const secret = f.addSecret({
    id: rawSecretId,
    site: loc.site,
    file: loc.file,
    line: loc.line,
    cls: 'HardwareBound',
    clsFromUser: true,
    unambiguousIntro: true,
    originDesc: `huks.generateKeyItem(${aliasStrValue})`,
  });

  const handleReprId = `ρ_handle(${aliasStrValue}@${loc.site}@${loc.ctx})`;
  if (f.options.disableHandle) {
    // -Handle 消融：不区分句柄与密钥材料，将别名字符串当作携带秘密的普通字符串
    f.addRepr({
      id: handleReprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      ctx: loc.ctx,
      form: 'Enc',
      encoding: 'utf8',
      container: 'ArkString',
      desc: `HUKS Alias '${aliasStrValue}' (ablation: -Handle)`,
    });
    f.addCarries(handleReprId, [secret.id]);
    f.addDirectCarries(handleReprId, [secret.id]);
  } else {
    f.addRepr({
      id: handleReprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      ctx: loc.ctx,
      form: 'Handle',
      container: 'ArkString',
      desc: `HUKS KeyHandle '${aliasStrValue}'`,
    });
    f.addHandle(handleReprId, [secret.id]);
  }
  return { secretId: secret.id, handleReprId };
}

/**
 * 3. 拷贝 / 编码 / 持久化 / 发送 / 日志转换：
 * 新建物理表示对象 ρ_new，其 form 与 container 在创建点固定，carries 继承自源表示对象集合 srcPts
 */
export function convertRepr(
  f: Facts,
  loc: SiteLocation,
  srcPts: Iterable<string>,
  form: Form | 'Inherit',
  container: Container,
  op: Op,
  extra?: {
    encoding?: EncodingKind;
    implicitIpc?: boolean;
    uncertain?: boolean;
    storageKey?: string;
  }
): string {
  const srcList = [...srcPts];
  let resolvedEncoding: EncodingKind | undefined = extra?.encoding;
  let anyUncertain = !!extra?.uncertain;

  // 计算单个源表示 r 在当前转换 (form, op) 下的有效目标形式：
  // 关键公理：对加密包装密文 (Wrapped)、句柄 (Handle)、单向摘要 (OneWay) 进行编码/解码/拷贝/持久化/日志/IPC，
  // 不会解除加密保护或将句柄/哈希逆转为明文材料（除非 op === 'unwrap' 或 'wrap' 或 'derive'）
  const computeSourceEffectiveForm = (r: Repr | undefined): Form => {
    if (op === 'wrap') return 'Wrapped';
    if (op === 'derive') return 'OneWay';
    if (op === 'unwrap') return form === 'Inherit' ? 'Raw' : form;
    if (!r) return form === 'Inherit' ? 'Raw' : form;
    if (r.form === 'Wrapped') return 'Wrapped';
    if (r.form === 'Handle') return 'Handle';
    if (r.form === 'OneWay') return 'OneWay';
    return form === 'Inherit' ? r.form : form;
  };

  let resolvedForm: Form = form === 'Inherit' ? 'Raw' : form;
  if (srcList.length > 0) {
    const effForms = srcList.map((id) => computeSourceEffectiveForm(f.reprs.get(id)));
    resolvedForm = effForms.reduce((acc, cur) => joinForm(acc, cur), effForms[0]);
    if (form === 'Inherit' && resolvedForm === 'Enc' && !resolvedEncoding) {
      const encSource = srcList.map((id) => f.reprs.get(id)).find((r) => r?.form === 'Enc');
      resolvedEncoding = encSource?.encoding ?? 'utf8';
    }
  }

  for (const s of srcList) {
    const r = f.reprs.get(s);
    if (r?.uncertain) anyUncertain = true;
  }

  const reprId = `ρ(${loc.site}@${loc.ctx})`;
  f.addRepr({
    id: reprId,
    site: loc.site,
    file: loc.file,
    line: loc.line,
    ctx: loc.ctx,
    form: resolvedForm,
    encoding: resolvedEncoding,
    container,
    implicitIpc: extra?.implicitIpc,
    uncertain: anyUncertain,
    storageKey: extra?.storageKey,
    desc: loc.desc,
  });

  for (const s of srcList) {
    const srcRepr = f.reprs.get(s);
    const sEffForm = computeSourceEffectiveForm(srcRepr);
    const ks = f.getCarries(s);
    if (ks.size > 0 && sEffForm !== 'OneWay' && sEffForm !== 'Handle') {
      f.addCarries(reprId, ks);
      if (sEffForm === 'Raw' || sEffForm === 'Enc' || sEffForm === 'KeyObj') {
        const directKs = f.getDirectCarries(s);
        f.addDirectCarries(reprId, directKs.size > 0 ? directKs : ks);
      }
    }
    const wraps = f.getWrapBy(s);
    if (wraps.size > 0 && sEffForm === 'Wrapped') {
      f.addWrapBy(reprId, wraps);
    }
    const handles = f.getHandle(s);
    if (handles.size > 0 && sEffForm === 'Handle') {
      f.addHandle(reprId, handles);
    }
    f.addProv({
      from: s,
      op,
      to: reprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      detail: loc.desc,
    });
  }

  return reprId;
}

/**
 * 4. 别名共享（如 napi_create_external_arraybuffer / napi_get_arraybuffer_info）：
 * 不新建独立的密钥副本，直接复用源表示对象集合（共享同一块物理内存）
 * 若消融开关 disableCopyAlias 开启，则退化为新建副本（无法感知对别名的 fill(0) 清零已作用于原件）
 */
export function aliasRepr(
  f: Facts,
  loc: SiteLocation,
  srcPts: Iterable<string>,
  targetContainer: Container
): Set<string> {
  if (f.options.disableCopyAlias) {
    // -CopyAlias 消融：不区分别名与拷贝，一律新建独立副本
    const copyId = convertRepr(f, loc, srcPts, 'Raw', targetContainer, 'copy');
    return new Set([copyId]);
  }
  const result = new Set<string>();
  for (const s of srcPts) {
    result.add(s);
    f.addProv({
      from: s,
      op: 'alias',
      to: s,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      detail: loc.desc ?? 'Shared memory alias',
    });
  }
  return result;
}

/**
 * 5. 密钥加密包装（Wrapping）：
 * 新建 Wrapped 表示对象，carries 继承自被包装密钥 keyPts，wrapBy 继承自包装密钥 kekPts（含 carries 或 handleOf）
 */
export function wrapRepr(
  f: Facts,
  loc: SiteLocation,
  keyPts: Iterable<string>,
  kekPts: Iterable<string>,
  container: Container
): string {
  const reprId = convertRepr(f, loc, keyPts, 'Wrapped', container, 'wrap');
  for (const kekReprId of kekPts) {
    // KEK 可能是明文/派生密钥表示 (carries)，也可能是 HUKS 密钥句柄 (handleOf)
    const carriedKeks = f.getCarries(kekReprId);
    if (carriedKeks.size > 0) {
      f.addWrapBy(reprId, carriedKeks);
    }
    const handleKeks = f.getHandle(kekReprId);
    if (handleKeks.size > 0) {
      f.addWrapBy(reprId, handleKeks);
    }
    f.addProv({
      from: kekReprId,
      op: 'wrap',
      to: reprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      detail: `Wrapped by KEK (${kekReprId})`,
    });
  }
  return reprId;
}

/**
 * 6. 单向派生（SHA-256 / SM3 摘要 / HMAC）：
 * 新建 OneWay 表示对象，carries 为空集（不可逆，不会还原原始秘密）
 */
export function oneWayRepr(
  f: Facts,
  loc: SiteLocation,
  srcPts: Iterable<string>,
  container: Container
): string {
  const reprId = `ρ_oneway(${loc.site}@${loc.ctx})`;
  f.addRepr({
    id: reprId,
    site: loc.site,
    file: loc.file,
    line: loc.line,
    ctx: loc.ctx,
    form: 'OneWay',
    container,
    desc: loc.desc ?? 'One-way cryptographic digest/MAC',
  });
  for (const s of srcPts) {
    f.addProv({
      from: s,
      op: 'derive',
      to: reprId,
      site: loc.site,
      file: loc.file,
      line: loc.line,
      detail: loc.desc ?? 'OneWay digest',
    });
  }
  return reprId;
}

/**
 * 7. 结构体 / 对象序列化（如 JSON.stringify(obj)）：
 * 递归收集对象自身及其所有字段 (fld) 的表示对象，若其中包含可恢复秘密，则生成的字符串承载该秘密
 */
export function serializeObjectRepr(
  f: Facts,
  loc: SiteLocation,
  objPts: Iterable<string>
): string {
  const allFieldReprs = f.getTransitiveFieldReprs(objPts);
  return convertRepr(f, loc, allFieldReprs, 'Enc', 'ArkString', 'encode', {
    encoding: 'json',
  });
}
