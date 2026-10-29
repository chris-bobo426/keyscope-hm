/**
 * report/human_explanations.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 面向普通用户与评审专家的全中文、可视化、白话文翻译与修复对比知识库
 */

export interface HumanProjectMeta {
  titleZh: string;
  subtitleZh: string;
  scenarioDescZh: string;
  group: 'realworld' | 'scenario_pair';
  familyCode?: string;
  isSafeSample?: boolean;
}

export const PROJECT_HUMAN_META: Record<string, HumanProjectMeta> = {
  // 8 个真实开源鸿蒙仓库
  openharmony_security_crypto_framework: {
    titleZh: '鸿蒙官方系统密码框架 (security_crypto_framework)',
    subtitleZh: 'C++ 异步密钥协商后未擦除共享密钥内存直接释放',
    scenarioDescZh:
      '这是 OpenHarmony 官方底层的密码算法框架仓库。在 ECDH/X25519 密钥协商的异步 C++ 实现中，程序生成共享密钥并复制给鸿蒙界面层后，在释放 C++ 原件内存前遗漏了清零操作（而同一文件里的同步接口却记得清零），导致共享密钥原件残留在内存堆中。',
    group: 'realworld',
  },
  openharmony_security_huks: {
    titleZh: '鸿蒙通用密钥库系统服务 (security_huks)',
    subtitleZh: '跨语言传入的密钥字节参数在 C++ 释放前未清零',
    scenarioDescZh:
      '这是 OpenHarmony 官方硬件密钥库（HUKS）的 NAPI 桥接层代码。当上层应用把密钥或派生参数通过字节数组传进 C++ 时，C++ 分配了堆内存保存它；但在使用完毕调用 FreeParsedParams 释放内存时，直接 free 掉了内存而没有先用 memset_s 抹除里面的密钥字节。',
    group: 'realworld',
  },
  ohos_mqtt: {
    titleZh: '鸿蒙 MQTT 物联网通信组件 (ohos_mqtt)',
    subtitleZh: 'SSL 私钥口令使用普通字符串传递且 C++ 内存未擦除',
    scenarioDescZh:
      '广泛应用于物联网设备连接的鸿蒙 MQTT 组件。它在解析 SSL 证书私钥口令（privateKeyPassword）和连接密码时，不仅使用了无法按需擦除的普通字符串，而且在 C++ 侧分配 char[] 数组使用后，既未抹零擦除也存在释放遗漏。',
    group: 'realworld',
  },
  ohos_coap: {
    titleZh: '鸿蒙 CoAP 轻量级物联网协议库 (ohos_coap)',
    subtitleZh: '会话认证令牌 (Token) 被直接打印到系统日志中',
    scenarioDescZh:
      '鸿蒙 CoAP 协议客户端组件。C++ 层将二进制会话认证令牌（baseToken）转换成十六进制文本后，直接调用 LOGI 打印到了系统 HiLog 日志里，同时又将其转换成不可变字符串传给 ArkTS 层。',
    group: 'realworld',
  },
  harmonyos_crypto_collection: {
    titleZh: '鸿蒙官方密码算法综合示例 (crypto_collection)',
    subtitleZh: 'AES-GCM 使用全 0 固定随机数 + 私钥存放在普通字符串中',
    scenarioDescZh:
      'HarmonyOS 官方密码算法集合示例工程。其中 AES-GCM 认证加密使用了写死的 12 个 0 作为初始向量（IV/Nonce），这在密码学上会导致认证加密彻底失效；此外还将 SM2 私钥存放在普通 UI 状态字符串中，且对称密钥字节数组用完未清零。',
    group: 'realworld',
  },
  ohos_crypto_js: {
    titleZh: '鸿蒙 CryptoJS 密码库应用 (ohos_crypto_js)',
    subtitleZh: 'PBKDF2 / EvpKDF 派生出的密钥直接通过日志与弹窗输出',
    scenarioDescZh:
      'OpenHarmony 社区广泛使用的 CryptoJS 密码库示例。代码在通过口令派生出密钥（EvpKDF / PBKDF2）后，直接把密钥转为普通字符串并通过 console.log 打印到控制台日志中。',
    group: 'realworld',
  },
  harmonyos_cipher: {
    titleZh: '鸿蒙加解密基础示例 (harmonyos_cipher)',
    subtitleZh: '在源码中硬编码固定 AES 密钥字符串',
    scenarioDescZh:
      'HarmonyOS 基础加解密示例工程，在模型文件中将 AES 对称加密密钥直接写死为 Base64 常量字符串，驻留在不可擦除的字符串内存中。',
    group: 'realworld',
  },
  harmonyos_preferences: {
    titleZh: '鸿蒙首选项存储标准示例 (harmonyos_preferences)',
    subtitleZh: '纯业务配置存储（不含密码密钥操作，安全通过体检）',
    scenarioDescZh:
      '这是用于检验系统“会不会乱报误报”的阴性对照工程。它频繁读写鸿蒙 Preferences 本地存储，但存放的都是普通界面配置而非密钥，本系统实测 0 误报通过。',
    group: 'realworld',
    isSafeSample: true,
  },

  // 8 大核心场景对比（A_Safe vs B_Risky）
  F1_v1_direct_A_Safe: {
    titleZh: '场景 1（安全示范）：只把“硬件钥匙编号”存入配置文件',
    subtitleZh: '真密钥锁在 HUKS 安全芯片里，配置文件只存别名句柄',
    scenarioDescZh:
      '好比把金条锁进银行保险箱，家里抽屉（Preferences 配置文件）只放一张写着保险箱编号的纸条。即使别人翻到了纸条，也拿不到真密钥。传统工具看到变量名叫 secretKeyMaterial 就会误报，本系统识别出它只是“钥匙编号（句柄）”，准确判定为安全。',
    group: 'scenario_pair',
    familyCode: 'F1',
    isSafeSample: true,
  },
  F1_v1_direct_B_Risky: {
    titleZh: '场景 1（危险反例）：把“真密钥”编码后直接写进配置文件',
    subtitleZh: '导出对称密钥真实字节并转成 Base64 存入本地文件',
    scenarioDescZh:
      '虽然开发者把变量名伪装成 publicConfigAlias（公开配置别名），但实际上调用了 getEncoded() 把真密钥导出来转成 Base64 写进了本地明文配置文件。攻击者一旦导出应用备份即可瞬间还原密钥。',
    group: 'scenario_pair',
    familyCode: 'F1',
    isSafeSample: false,
  },
  F2_v1_direct_A_Safe: {
    titleZh: '场景 2（安全示范）：C++ 生成密钥传给鸿蒙层后，双端彻底抹零',
    subtitleZh: '全程使用字节数组承载，用完后 C++ 与 ArkTS 两侧均执行安全擦除',
    scenarioDescZh:
      'C++ 调用 RAND_bytes 生成随机密钥并通过二进制缓冲区传给 ArkTS，C++ 侧立即调用 memset_s 抹除原件，ArkTS 侧用完后立即调用 .fill(0) 抹除副本，全程不转成普通字符串，也不写日志。',
    group: 'scenario_pair',
    familyCode: 'F2',
    isSafeSample: true,
  },
  F2_v1_direct_B_Risky: {
    titleZh: '场景 2（危险反例）：C++ 派生密钥后转成普通字符串并打印日志',
    subtitleZh: '跨语言返回不可擦除的字符串，且直接输出到系统日志',
    scenarioDescZh:
      'C++ 调用 EVP_PKEY_derive 派生出密钥后，通过 napi_create_string_utf8 把密钥变成了无法抹零的普通文本字符串传回鸿蒙层，紧接着又打印到了系统日志中，造成内存驻留与日志双重泄密。',
    group: 'scenario_pair',
    familyCode: 'F2',
    isSafeSample: false,
  },
  F3_v1_direct_A_Safe: {
    titleZh: '场景 3（安全示范）：用硬件芯片主密钥给会话密钥“上锁”后再保存',
    subtitleZh: '被保存的是加密后的密文，且开锁的主密钥锁在硬件芯片内不可导出',
    scenarioDescZh:
      '会话密钥在写入本地配置文件前，先用 HUKS 硬件芯片里的主密钥进行了加密包装（Wrap），并且把原始明文数组抹零。因为开锁的主密钥在硬件芯片里永远拿不出来，所以哪怕对包装后的密文再做 Base64 编码或保存到本地，也绝对无法被还原。',
    group: 'scenario_pair',
    familyCode: 'F3',
    isSafeSample: true,
  },
  F3_v1_direct_B_Risky: {
    titleZh: '场景 3（危险反例）：给密钥上了锁，却把“开锁密码”存在同一个文件里',
    subtitleZh: '被包装的密文与明文主密钥（KEK）同时写入同一个 Preferences 存储',
    scenarioDescZh:
      '开发者虽然对会话密钥进行了加密包装，但却犯了一个致命错误：把用来加密它的主密钥（appKekBytes）也以明文形式存进了同一个配置文件里！这就像把保险箱和保险箱钥匙放在同一个抽屉里，攻击者拿到文件后先取出主密钥，就能直接解开会话密钥。',
    group: 'scenario_pair',
    familyCode: 'F3',
    isSafeSample: false,
  },
  F4_v1_direct_A_Safe: {
    titleZh: '场景 4（安全示范）：多条代码分支合流，但两条分支都是安全硬件句柄',
    subtitleZh: '无论走哪条分支，最终写入存储的都只是硬件密钥编号',
    scenarioDescZh:
      '代码在 if/else 两个分支中分别选择了主用或备用 HUKS 硬件密钥别名，合流后写入配置文件。两侧都不含真密钥字节，安全通过。',
    group: 'scenario_pair',
    familyCode: 'F4',
    isSafeSample: true,
  },
  F4_v1_direct_B_Risky: {
    titleZh: '场景 4（危险反例）：多分支合流时，其中一条分支混入了真实长期密钥',
    subtitleZh: '一条分支是公开盐值，另一条分支是长期密钥，合流后写入存储',
    scenarioDescZh:
      'if 分支放入的是公开数据，但 else 分支放入的是真实的长期密钥（LongTerm），合流到一个变量后写入本地文件。本系统通过半格单调合流算法，不受分支先后顺序影响，准确抓出其中混入的真密钥泄露。',
    group: 'scenario_pair',
    familyCode: 'F4',
    isSafeSample: false,
  },
  F5_v1_direct_A_Safe: {
    titleZh: '场景 5（安全示范）：共用转换函数，但只把“公开随机数”打印到日志',
    subtitleZh: '公开数据与真密钥先后调用同一个 toHex 函数，互不污染',
    scenarioDescZh:
      '程序里有一个公共的转十六进制函数。开发者先用它转换公开的随机初始向量（IV）并打印日志，再用它转换真密钥但严格留在受控区。传统工具会把两次调用混为一谈导致误报，本系统具备调用点上下文区分能力，准确判定为安全。',
    group: 'scenario_pair',
    familyCode: 'F5',
    isSafeSample: true,
  },
  F5_v1_direct_B_Risky: {
    titleZh: '场景 5（危险反例）：通过公共转换函数把“真密钥”转成文本并打印日志',
    subtitleZh: '追踪密钥穿过辅助函数后的去向，准确捕获日志泄露',
    scenarioDescZh:
      '真密钥传入公共转换函数变成十六进制字符串后，返回值被传给 hilog.info 打印到系统日志，触发不可变字符串驻留与日志泄露告警。',
    group: 'scenario_pair',
    familyCode: 'F5',
    isSafeSample: false,
  },
  F6_v1_direct_A_Safe: {
    titleZh: '场景 6（安全示范）：对密钥做 SHA-256 单向不可逆摘要后再保存指纹',
    subtitleZh: '单向哈希值无法反推原密钥，公开保存校验指纹完全安全',
    scenarioDescZh:
      '为了核对密钥版本，程序对密钥做了 SHA-256 单向哈希运算，把算出来的哈希指纹存入配置文件。因为单向哈希在数学上不可逆，无法还原出原密钥，本系统不会误报。',
    group: 'scenario_pair',
    familyCode: 'F6',
    isSafeSample: true,
  },
  F6_v1_direct_B_Risky: {
    titleZh: '场景 6（危险反例）：误把可逆的 Base64 编码当成“安全摘要”保存',
    subtitleZh: 'Base64 不是加密也不是哈希，任何人都能一秒解码还原真密钥',
    scenarioDescZh:
      '开发者把密钥用 Base64Helper 编码后存入配置文件。Base64 只是换了一种字母写法（可逆编码），没有任何保密作用，解码后就是原始明文密钥。',
    group: 'scenario_pair',
    familyCode: 'F6',
    isSafeSample: false,
  },
  F7_v1_direct_A_Safe: {
    titleZh: '场景 7（安全示范）：对象里有密钥也有公开字段，但只取出公开字段外发',
    subtitleZh: '精确区分同一个对象里的不同属性字段，不冤枉合规代码',
    scenarioDescZh:
      '复合对象里同时装着公开的 IV 和敏感的会话密钥，但程序只把公开的 IV 字段写进了本地文件，敏感密钥字段被妥善清零。',
    group: 'scenario_pair',
    familyCode: 'F7',
    isSafeSample: true,
  },
  F7_v1_direct_B_Risky: {
    titleZh: '场景 7（危险反例）：用 JSON.stringify 把含密钥的整个对象打包跨进程发送',
    subtitleZh: '对象整体序列化时会将内部的敏感密钥字段一并暴露',
    scenarioDescZh:
      '程序调用 JSON.stringify 把整个对象打包成字符串，通过跨进程通信（IPC / Preferences）发送出去，导致藏在对象属性里的会话密钥被连带泄露。',
    group: 'scenario_pair',
    familyCode: 'F7',
    isSafeSample: false,
  },
  F8_v1_direct_A_Safe: {
    titleZh: '场景 8（安全示范）：C++ 与鸿蒙界面层共享同一块内存，一处抹零处处生效',
    subtitleZh: '使用外部共享内存 (Alias)，在 ArkTS 侧调用 .fill(0) 即可直接擦除底层物理内存',
    scenarioDescZh:
      'C++ 通过 napi_create_external_arraybuffer 将内存直接映射给鸿蒙界面层（双方指向同一块物理内存，没有产生复印件）。用完后调用 .fill(0) 就把底层唯一的物理内存彻底抹零了。',
    group: 'scenario_pair',
    familyCode: 'F8',
    isSafeSample: true,
  },
  F8_v1_direct_B_Risky: {
    titleZh: '场景 8（危险反例）：跨语言“复印”了密钥，只销毁了复印件却忘了销毁 C++ 原件',
    subtitleZh: 'napi_create_buffer_copy 会复制新内存，ArkTS 侧 .fill(0) 无法擦除 C++ 原件',
    scenarioDescZh:
      'C++ 使用 napi_create_buffer_copy 把密钥传给鸿蒙层时，底层实际上“复印”了一份新内存。开发者在鸿蒙界面层乖乖调用了 .fill(0)，以为密钥已经销毁了，但其实只销毁了界面层的“复印件”，C++ 里的“原件”根本没做安全擦除（或用了会被编译器优化删掉的普通 memset），仍然明文留在内存里！',
    group: 'scenario_pair',
    familyCode: 'F8',
    isSafeSample: false,
  },
};

export interface RuleHumanExplanation {
  titleZh: string;
  tagZh: string;
  plainWhatHappened: string;
  plainWhyDangerous: string;
  plainHowToFix: string;
  beforeCodeExample: string;
  afterCodeExample: string;
}

export const RULE_HUMAN_MAP: Record<string, RuleHumanExplanation> = {
  V1: {
    titleZh: '把敏感密钥转成了“无法擦除的普通文字字符串”',
    tagZh: '内存长期残留风险 (V1)',
    plainWhatHappened:
      '程序把原本存放在字节数组（Uint8Array）里的二进制密钥，通过 Base64、Hex（十六进制）或 UTF-8 解码变成了鸿蒙 ArkTS 的普通文字字符串（String），或者直接在代码里用字符串写了密钥。',
    plainWhyDangerous:
      '在鸿蒙方舟运行时（以及 JS/V8 引擎）中，普通字符串（String）一旦创建就是“不可修改”的！哪怕你用完后写 keyStr = null，那串密钥文字依然原封不动地留在手机内存里，直到很久以后垃圾回收器覆盖它。攻击者只要导出进程内存快照，就能直接搜出明文密钥。',
    plainHowToFix:
      '全程使用可擦除的字节数组（Uint8Array）保存和传递密钥，不要调用 Base64Helper.encodeToStringSync / toString / napi_create_string_utf8 把密钥转成字符串；用完后立即调用 keyBytes.fill(0) 把每个字节抹成 0。',
    beforeCodeExample: `// ❌ 危险做法：把密钥转成普通字符串，无法从内存中主动抹除
let b64 = new util.Base64Helper();
let keyStr: string = b64.encodeToStringSync(rawKeyBytes);
// 即使后续写 keyStr = ''，原字符串依然残留在内存堆中`,
    afterCodeExample: `// ✅ 安全做法：全程使用 Uint8Array 字节数组，用完后立即用 .fill(0) 原地抹零
let keyBytes: Uint8Array = sessionKey.getEncoded().data;
try {
  // 执行加解密业务操作...
} finally {
  keyBytes.fill(0); // 将底层内存全部覆写为 0，物理内存扫描 0 残留
}`,
  },
  V2: {
    titleZh: '把可还原的密钥写进了本地明文配置文件或跨进程通道',
    tagZh: '本地文件/跨进程泄密 (V2)',
    plainWhatHappened:
      '程序把未加密的密钥（或者虽然加密包装了密钥，但把用来开锁的主密钥 KEK 也明文放在了同一个地方）写入了鸿蒙 Preferences 首选项、数据库、本地文件，或通过 Want 跨进程发送了出去。',
    plainWhyDangerous:
      '本地 Preferences 文件和应用备份很容易被攻击者通过备份导出、root 读取或同设备恶意组件截获。如果存的是明文密钥、Base64 编码密钥，或者“密文+开锁密码放一起”，攻击者能直接拿到密钥解开所有用户数据。',
    plainHowToFix:
      '在鸿蒙系统中，应当使用 @ohos.security.huks（硬件通用密钥库）生成并保管主密钥，密钥本体永远锁在安全芯片（TEE）内；如果确实需要持久化保存会话密钥，必须用 HUKS 硬件主密钥加密包装（Wrap）后再保存密文，绝不能把明文主密钥一起存进文件。',
    beforeCodeExample: `// ❌ 危险做法：把真密钥或明文主密钥直接写进本地 Preferences 配置文件
let rawKey = symKey.getEncoded().data;
pref.putSync('saved_secret_key', rawKey); // 或把明文 KEK 与被包装密文存在同一文件`,
    afterCodeExample: `// ✅ 安全做法：由 HUKS 硬件安全芯片保管主密钥，配置文件只存“钥匙别名”或受硬件保护的密文
let huksAlias = 'my_hardware_kek_alias';
await huks.generateKeyItem(huksAlias, huksOptions); // 真密钥在安全芯片内生成，永不导出
let wrappedCipher = await huks.wrapKey(sessionRaw, huksAlias);
sessionRaw.fill(0); // 立即抹除内存中的明文会话密钥
pref.putSync('wrapped_session_key', wrappedCipher); // 仅保存硬件加密后的密文`,
  },
  V3: {
    titleZh: '把敏感密钥或认证令牌直接打印到了系统日志里',
    tagZh: '系统日志泄密 (V3)',
    plainWhatHappened:
      '程序在调试或运行过程中，调用了 console.log、hilog.info 或 C++ 侧的 LOGI / OH_LOG_INFO，把包含密钥、派生结果或会话认证令牌（Token）的变量直接输出到了系统日志通道。',
    plainWhyDangerous:
      '手机连接电脑调试（hdc hilog）、崩溃日志上传或第三方日志收集组件都能直接读取系统日志。把密钥打印到日志里等于把保险箱密码贴在公告栏上。',
    plainHowToFix:
      '立即删除打印密钥、口令或认证 Token 内容的代码；如果调试时必须确认密钥是否生成成功，只能打印“密钥长度”或“脱敏状态（如 [已生成 32 字节密钥]）”，绝不能打印密钥内容本身。',
    beforeCodeExample: `// ❌ 危险做法：直接把派生出的密钥或 Token 文本打印到日志
console.log("pbkdf2-compute=" + derivedKeyStr);
LOGI("Random tokenString string: %s\\n", tokenString.c_str());`,
    afterCodeExample: `// ✅ 安全做法：删除明文密钥日志，仅记录脱敏状态或字节长度
hilog.info(0x0000, 'Crypto', '密钥派生成功，字节长度: %{public}d', derivedKeyBytes.byteLength);`,
  },
  E1_M4: {
    titleZh: '密钥用完后忘记擦除内存，或擦除代码被编译器“优化删掉”了',
    tagZh: '内存未清零/原件残留 (E1_M4)',
    plainWhatHappened:
      '存在三种常见漏洞情形：(1) 密钥字节数组用完后直接释放（free / HcfFree / HKS_FREE / delete[]）而没有先把内容抹成 0；(2) C++ 通过复印方式（napi_create_buffer_copy）把密钥传给鸿蒙界面层后，只抹零了界面层的复印件，却忘了抹零 C++ 里的原件；(3) 在 C++ 里用了普通的 memset 清零，结果开启 -O2 编译优化时被编译器当成“无用代码”自动删掉了。',
    plainWhyDangerous:
      '操作系统的 free() 或 delete[] 只会给内存贴上“已空闲”标签，并不会把里面原有的密钥字节抹掉！只要这块内存还没被别的程序刚好覆盖，攻击者扫描进程内存就能把刚才用过的密钥完整捞出来。',
    plainHowToFix:
      '在释放任何密钥缓冲区之前（包括所有错误提前返回分支），C/C++ 侧必须调用防编译器优化的安全清零函数（如 memset_s、OPENSSL_cleanse、HcfBlobDataClearAndFree），ArkTS 侧必须调用 uint8Arr.fill(0)；跨语言拷贝时，C++ 原件与 ArkTS 复印件两边都要各自清零！',
    beforeCodeExample: `// ❌ 危险做法：释放 C++ 密钥结构体前未抹零，或使用了会被 -O2 删掉的普通 memset
if (ctx->returnSecret.data != nullptr) {
    HcfFree(ctx->returnSecret.data); // 直接释放，密钥字节原封不动留在堆内存里！
    ctx->returnSecret.data = nullptr;
}`,
    afterCodeExample: `// ✅ 安全做法：调用防编译器优化的 HcfBlobDataClearAndFree / memset_s 先抹零再释放
if (ctx->returnSecret.data != nullptr) {
    (void)memset_s(ctx->returnSecret.data, ctx->returnSecret.len, 0, ctx->returnSecret.len);
    HcfFree(ctx->returnSecret.data);
    ctx->returnSecret.data = nullptr;
}`,
  },
  E2_M3: {
    titleZh: 'AES-GCM / SM4-GCM 加密使用了全 0 或固定不变的初始向量 (IV/Nonce)',
    tagZh: '固定随机数导致加密失效 (E2_M3)',
    plainWhatHappened:
      '程序在使用 GCM / CCM / CTR 等认证加密模式时，传入了写死的固定字节数组（例如 12 个全 0：[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]）作为初始向量（IV / Nonce）。',
    plainWhyDangerous:
      '在 GCM 模式下，“同一个密钥 + 同一个 IV”一旦加密两段不同的数据，攻击者只需要把两段密文简单做一次异或（XOR）运算，就能直接抵消掉加密密钥流，瞬间算出明文内容，并伪造任意合法的认证标签（AuthTag）！',
    plainHowToFix:
      '每次执行加密前，必须调用鸿蒙安全随机数生成器 cryptoFramework.createRandom().generateRandomSync(12) 生成全新的 12 字节随机 IV。',
    beforeCodeExample: `// ❌ 危险做法：使用写死的 12 个 0 作为 GCM 初始向量
let arr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 致命漏洞：固定全零 Nonce！
let ivBlob: cryptoFramework.DataBlob = { data: new Uint8Array(arr) };`,
    afterCodeExample: `// ✅ 安全做法：每次加密均调用密码学安全随机数生成器产生全新 12 字节随机 Nonce
let rand = cryptoFramework.createRandom();
let ivBlob: cryptoFramework.DataBlob = rand.generateRandomSync(12);`,
  },
  E3_M2: {
    titleZh: '明文密钥在导入 HUKS 硬件芯片前已经在外面转成了不安全的字符串',
    tagZh: '入芯前明文暴露 (E3_M2)',
    plainWhatHappened:
      '虽然程序最后把密钥导入了 HUKS 硬件密钥库，但在导入之前，这把密钥已经在普通业务层被转成了不可擦除的字符串或留下了未清零的明文副本。',
    plainWhyDangerous:
      '好比把机密文件锁进保险柜之前，先在敞开的大厅里复印了好几份还扔在桌子上。即使最后锁进了硬件芯片，外面的内存残留依然会泄密。',
    plainHowToFix:
      '优先在 HUKS 硬件内部直接生成密钥（huks.generateKeyItem）或使用安全导入（huks.importWrappedKeyItem）；若必须外部导入，确保全程只用 Uint8Array 并在导入完成后立即 .fill(0) 清零。',
    beforeCodeExample: `// ❌ 危险做法：先用字符串拼接明文密钥，再导入 HUKS
let plainKeyStr = 'my_raw_secret_key_material_32b';
let keyBytes = new Uint8Array(buffer.from(plainKeyStr, 'utf-8').buffer);
await huks.importKeyItem(alias, options);`,
    afterCodeExample: `// ✅ 安全做法：直接在 HUKS 硬件边界内生成密钥，或使用加密包装导入
await huks.generateKeyItem(alias, generateOptions); // 密钥从诞生起就不离开硬件安全边界`,
  },
};

export const CONTAINER_ZH_MAP: Record<string, { nameZh: string; icon: string; safetyDesc: string }> = {
  HUKS: { nameZh: 'HUKS 硬件安全芯片边界', icon: '🛡️', safetyDesc: '硬件隔离保护（安全）' },
  HuksHandle: { nameZh: 'HUKS 硬件钥匙编号（句柄）', icon: '🏷️', safetyDesc: '仅含编号不含真密钥（安全）' },
  ArkKeyObj: { nameZh: '鸿蒙密码库密钥对象 (KeyObj)', icon: '🔐', safetyDesc: '受控密钥对象' },
  ArkBuffer: { nameZh: '鸿蒙字节数组 (Uint8Array)', icon: '📦', safetyDesc: '可随时调用 .fill(0) 抹零擦除' },
  NativeHeap: { nameZh: 'C/C++ 原生内存缓冲区', icon: '⚙️', safetyDesc: '释放前必须调用 memset_s 抹零' },
  ArkString: { nameZh: '鸿蒙普通文本字符串 (String)', icon: '⚠️', safetyDesc: '高危：一旦创建无法从内存中抹除！' },
  Storage: { nameZh: '本地持久化配置文件 (Preferences/数据库)', icon: '💾', safetyDesc: '高危：落盘保存，易被备份提取！' },
  IPC: { nameZh: '跨进程通信通道 (Want/RPC)', icon: '📡', safetyDesc: '高危：跨组件传输暴露！' },
  Log: { nameZh: '系统控制台与调试日志 (HiLog/console)', icon: '📢', safetyDesc: '极高危：明文直接打印到日志！' },
};

export const FORM_ZH_MAP: Record<string, string> = {
  Raw: '原始明文密钥字节',
  Enc: '可逆编码文本 (Base64/十六进制，可一秒还原)',
  KeyObj: '密码库密钥结构体',
  Wrapped: '已加密上锁的密文 (Wrapped)',
  Handle: '钥匙编号/引用别名 (不含密钥本体)',
  OneWay: '单向不可逆哈希值 (无法反推原密钥)',
};

export const SECRET_CLASS_ZH_MAP: Record<string, string> = {
  Session: '临时会话密钥 / 认证令牌',
  LongTerm: '长期主密钥 / 证书私钥 / 核心口令',
  HardwareBound: 'HUKS 硬件芯片根密钥 (不可导出)',
};

export const OP_ZH_MAP: Record<string, string> = {
  encode: '转成文本编码 (Base64/Hex)',
  decode: '解码还原为字节',
  copy: '复印到新内存 (原件与复印件独立)',
  alias: '共享同一块内存 (原位映射)',
  napi: '跨 C++ 与鸿蒙界面层传递 (NAPI)',
  wrap: '使用主密钥加密上锁 (Wrap)',
  oneway: '执行单向不可逆哈希 (SHA256/SM3)',
  persist: '写入本地配置文件 (Preferences/存储)',
  ipc: '通过跨进程通道发送 (IPC)',
  log: '打印输出到系统日志 (HiLog/console)',
  export: '从密钥对象导出原始字节',
  serialize: '整个对象打包成 JSON 字符串',
};
