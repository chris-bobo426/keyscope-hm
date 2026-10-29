# API语义核对

文档镜像固定到 `openharmony/docs@f41b9345badd47c7ab0c263344cd7f4b5a549afb`。该 GitHub 镜像快照不能代表2026年10月所有最新 SDK；正式实验需保存实际 SDK 头文件/声明版本。以下是建模依据和应验证的条件，没有改动当前实现。

## 密钥、表示与存储

| 对象/操作 | 核实后的边界 | 实验/建模要求 |
|---|---|---|
| HUKS alias | 别名是查找/使用密钥的标识，不等于密钥字节 | 别名公开不自动构成密钥材料泄露；另评估攻击者是否可调用该句柄进行操作 |
| `huks.exportKeyItem` | 文档返回的是非对称公钥材料 | 不能将所有 export 都标成私钥/对称密钥泄露 |
| `generateKeyItem` | 需要具体密钥属性和合法参数 | `new Object()` 占位不能证明有效生成；必须编译并实际成功调用 |
| 自定义 `huks.wrapKey` | 此次核对的官方声明未找到此接口 | 若为辅助函数，必须提供实现；可按官方会话式加密 API 实现包装用途，但不可伪装成 SDK API |
| `importWrappedKeyItem` | 安全导入流程不等于通用导出/包装函数 | 绑定支持算法、API版本和封装格式 |
| `getEncoded()` | 返回编码数据对象；需区分公钥、私钥、对称密钥，跟踪 `.data` | 不能按方法短名统一作为秘密源 |
| Base64/hex | 可逆表示，不提供保密性 | 编码 Raw 仍可恢复；编码 Wrapped 仍依赖 KEK，不变成裸密钥 |
| 任意密钥字节→UTF-8 string | 无效字节可能被替换，转换不一定可逆 | 使用 hex/Base64 验证精确恢复；UTF-8 另记损失/部分泄露，不能无条件标为可精确恢复 |
| SHA-256 等摘要 | 高熵输入下通常不能直接恢复原密钥；低熵口令仍可枚举 | 标注输入熵与威胁模型，不把 hash 通用当成安全净化器 |
| `AppStorage` | 应用内存状态容器 | 本身不等于落盘 |
| `PersistentStorage` | 显式绑定属性产生持久化语义 | 需要跟踪与 AppStorage 属性的关联、实际支持值类型和写入时刻 |
| Preferences | XML 等模式涉及内存缓存与 flush；文档另有 GSKV 模式 | 固定存储模式/API版本；`put` 不足以证明当时已落盘，也不能跨版本断言永不落盘 |

依据：[HUKS API](downloads/docs/js-apis-huks.md)、[安全导入](downloads/docs/huks-key-import-overview.md)、[会话加解密](downloads/docs/huks-encryption-decryption-arkts.md)、[CryptoFramework](downloads/docs/js-apis-cryptoFramework.md)、[Base64](downloads/docs/util-base64.md)、[RFC4648](downloads/docs/rfc4648-base64.txt)、[AppStorage](downloads/docs/appstorage.md)、[PersistentStorage](downloads/docs/persistentstorage.md)、[Preferences](downloads/docs/preferences.md)。

## N-API 与 Native 输出参数

下面索引全部采用 C 函数形参的 **0起始索引**，包括 `env`。解析器必须区分“产生 JS 值的出参”“密钥字节的存储区”“长度/偏移”，不能只匹配函数名。

| 函数/操作 | 关键位置与关系 | 必测反例 |
|---|---|---|
| `napi_create_buffer_copy(env,len,data,result_data,result)` | 输入字节 args[2]；新字节指针 out args[3]；JS结果 out args[4]；复制 | 清零原件不能清零副本；清零副本不能清零原件 |
| `napi_create_arraybuffer(env,len,data,result)` | 新存储区指针 out args[2]，JS结果 out args[3]；后续 memcpy 才携带原秘密 | 新建空 buffer 本身不是秘密源 |
| `napi_create_external_arraybuffer(env,data,len,finalizer,hint,result)` | args[1] 是共享 Native 存储；args[5] 为 JS结果 | 同区域别名；finalizer负责生命周期，创建 wrapper 不等于另复制一份 |
| `napi_get_arraybuffer_info(env,value,data,len)` | value args[1]；存储指针 out args[2] | 取指针本身不创建副本 |
| `napi_get_typedarray_info(env,value,type,len,data,arraybuffer,offset)` | data out args[4]、arraybuffer out args[5]、offset out args[6] | 不能照搬上一行，把 type out 当字节指针；长度按元素、字节偏移需换算 |
| `napi_create_string_utf8(env,str,len,result)` | 复制到受管字符串，result out args[3] | 原 buffer 清零不表示字符串被清除；任意二进制 UTF-8 可逆性另判 |
| `napi_get_value_string_utf8(env,value,buf,size,result)` | 拷贝字符到 args[2]；result out 是长度 | 不要把返回长度变量当密钥容器 |
| `EVP_PKEY_derive(ctx,key,keylen)` | key out args[1]，keylen in/out args[2] | args[0] 是上下文；key=NULL 查询长度不是产生秘密字节 |
| `PKCS5_PBKDF2_HMAC(pass,passlen,salt,saltlen,iter,digest,keylen,out)` | 输出 args[7]，keylen args[6] | **HMAC版本有8个形参**；不得与7参数的 SHA1 便捷版本混用 |

依据：[OpenHarmony N-API](downloads/docs/napi-data-types-interfaces.md)、[原生接口](downloads/docs/openharmony-native-napi.md)、[Node官方API](downloads/docs/node-api.html)、[OpenSSL derive](https://docs.openssl.org/3.0/man3/EVP_PKEY_derive/)、[OpenSSL PBKDF2](https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/)。Node 文档提供参考语义，不证明 HarmonyOS 某版本实现或 API 支持情况完全相同。

## 密码条件与清零

- HKDF 的 salt 可以省略；RFC5869提供缺省处理。不能将“salt常量/缺省”直接推广为所有 HKDF 不安全。口令派生还涉及盐的唯一性和工作因子，不能用 HKDF替代口令加固。[RFC5869](downloads/docs/rfc5869.txt)
- AEAD 需要遵守具体算法的 nonce 要求。GCM 同密钥下 nonce 唯一性是核心条件，正确维护的计数器也可能满足，不能把“不是随机数”一律判为复用。[RFC5116](downloads/docs/rfc5116-aead.txt)、[NIST GCM](downloads/papers/NIST-SP800-38D.pdf)
- 包装保护不能仅由函数名认定。需要可信算法、完整性/认证、参数、KEK可访问性、解包权限和生命周期。AES Key Wrap 的定义可参考 [RFC3394](downloads/docs/rfc3394.txt)；该文档不证明项目某个辅助函数正确实现了它。
- 清零是“某时刻、某区域、某字节范围”的事实。写过0不等于所有副本均清零，不等于异常/早返回路径也清零，更不等于先前日志/持久化泄露被撤回。
- 普通 `memset` 在特定上下文可能被优化消除，但必须检查目标编译器、优化选项、LTO与最终链接产物。[CWE-14](https://cwe.mitre.org/data/definitions/14.html) 提供失效类别，不支持“所有-O2必消除”的断言。
- NativeHeap、ArkBuffer、ArkKeyObj 不能仅凭“可清零/框架持有”归为绝对安全域。内存读取攻击者可见性与生命周期策略是两个独立维度。
- HUKS 的硬件保护取决于设备与安全环境。[官方 HUKS README](downloads/docs/huks-readme.md) 说明开源环境/部分系统中的模拟实现边界；模拟器成功不证明 TEE 隔离。

## 堆观测能力

[hidebug文档](downloads/docs/hidebug.md) 包含 `dumpJsHeapData`，基本API与较新 `needClean` 重载有不同版本要求。需按目标版本核对；JS堆快照不保证覆盖 Native 字节区，也不保证搜索算法能发现全部编码/分片副本。DevEco网页本次只获得页面壳，具体工具操作仍应在安装环境验证。

如果目标进程里仍保存“要查找的密钥字符串”，观测器本身会制造阳性。应把真值留在独立控制进程，测试进程只保留待测路径必需材料；每次独立启动，记录快照覆盖范围、GC是否实际发生、错误与空结果。Node代理实验单列，不合并进 ArkTS真机统计。
