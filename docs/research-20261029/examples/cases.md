# 40个待验证场景

状态：全部为设计假设，尚未作为本资料包中的实验执行。`possible`表示条件分支下可能；`unknown`表示现有信息不足；`not_applicable`表示该对象/条件不属于密钥恢复阳性。负例只在列出的假设下成立。

| ID | 场景 | F族 | 预期恢复分类 |
|---|---|---|---|
| [K01](#k01) | 句柄落盘 | F1 | not_recoverable_under_assumptions |
| [K02](#k02) | Base64材料落盘 | F1 | recoverable |
| [K03](#k03) | 公钥导出 | F1 | not_applicable |
| [K04](#k04) | 公开IV日志 | F5 | not_applicable |
| [K05](#k05) | 密钥日志 | F5 | recoverable |
| [K06](#k06) | 高熵密钥摘要 | F6 | not_recoverable_under_assumptions |
| [K07](#k07) | 受保护包装再编码 | F3 | not_recoverable_under_assumptions |
| [K08](#k08) | 密文与KEK同存 | F3 | recoverable |
| [K09](#k09) | 多层包装 | F3 | recoverable |
| [K10](#k10) | 包装与Raw合流 | F3 | possible |
| [K11](#k11) | 跨域可组合KEK | F3 | recoverable |
| [K12](#k12) | 无根包装循环 | F3 | not_recoverable_under_assumptions |
| [K13](#k13) | 有根包装循环 | F3 | recoverable |
| [K14](#k14) | 包装参数失效 | F3 | unknown |
| [K15](#k15) | 同变量多秘密 | F4 | possible |
| [K16](#k16) | 同helper不同上下文 | F5 | possible |
| [K17](#k17) | 结构体序列化 | F7 | recoverable |
| [K18](#k18) | external共享清零 | F8 | not_recoverable_under_assumptions |
| [K19](#k19) | 副本清零不清原件 | F8 | recoverable |
| [K20](#k20) | 原件清零字符串仍存 | F2 | recoverable |
| [K21](#k21) | 局部view清零 | F8 | possible |
| [K22](#k22) | typedarray输出参数 | F2 | possible |
| [K23](#k23) | ECDH输出 | F2 | possible |
| [K24](#k24) | PBKDF2输出 | F2 | possible |
| [K25](#k25) | 汇点前必经清零 | F8 | not_recoverable_under_assumptions |
| [K26](#k26) | 泄露后清零 | F8 | recoverable |
| [K27](#k27) | AppStorage内存状态 | 扩展 | not_recoverable_under_assumptions |
| [K28](#k28) | 显式持久化绑定 | 扩展 | recoverable |
| [K29](#k29) | XML Preferences尚未flush | 扩展 | unknown |
| [K30](#k30) | XML Preferences完成flush | 扩展 | recoverable |
| [K31](#k31) | HKDF缺省salt | 扩展 | not_applicable |
| [K32](#k32) | GCM计数器nonce | 扩展 | not_applicable |
| [K33](#k33) | 低熵秘密摘要 | F6 | recoverable |
| [K34](#k34) | 长传播链 | 扩展 | recoverable |
| [K35](#k35) | 求解顺序不变性 | 扩展 | possible |
| [K36](#k36) | 循环与phi收敛 | 扩展 | possible |
| [K37](#k37) | 路径相关KEK与密文 | F4 | not_recoverable_under_assumptions |
| [K38](#k38) | 同名方法不同符号 | 扩展 | not_applicable |
| [K39](#k39) | 未知Native摘要 | F2 | unknown |
| [K40](#k40) | 脱敏日志实参与字符串 | 扩展 | not_applicable |

<a id="k01"></a>
## K01 句柄落盘

- 场景：仅持久化HUKS别名，不输出密钥材料
- 成立条件：存储读取者无应用解密/签名调用权限
- 预期：not_recoverable_under_assumptions；无材料泄露；句柄能力另审
- 配对变化：改为getEncoded().data后编码落盘
- 验证方式：检查持久化内容与密钥身份，不将alias字符串当真值
- 依据：[HUKS](../downloads/docs/js-apis-huks.md)

<a id="k02"></a>
## K02 Base64材料落盘

- 场景：随机对称密钥字节Base64后写XML Preferences并flush
- 成立条件：攻击者能读该存储，编码完整
- 预期：recoverable；明文等价持久化
- 配对变化：只保存不可用的alias
- 验证方式：外部解码与独立真值逐字节比对
- 依据：[RFC4648](../downloads/docs/rfc4648-base64.txt)、[Preferences](../downloads/docs/preferences.md)

<a id="k03"></a>
## K03 公钥导出

- 场景：exportKeyItem导出公钥并保存
- 成立条件：确认对象是非对称公钥而非私钥/对称材料
- 预期：not_applicable；公钥不标作秘密；授权另判
- 配对变化：替换为私钥编码路径并单独验证
- 验证方式：确认官方API返回类型与密钥种类
- 依据：[HUKS](../downloads/docs/js-apis-huks.md)

<a id="k04"></a>
## K04 公开IV日志

- 场景：toHex(iv)后记录日志
- 成立条件：iv确为公开参数，未复用且不包含秘密
- 预期：not_applicable；无密钥材料泄露
- 配对变化：同一辅助函数接收密钥
- 验证方式：参数身份追踪及日志值核对
- 依据：[NIST GCM](../downloads/papers/NIST-SP800-38D.pdf)、[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k05"></a>
## K05 密钥日志

- 场景：toHex(secret)后记录日志
- 成立条件：日志读取者可以取得完整hex
- 预期：recoverable；日志泄露
- 配对变化：相同helper仅处理公开IV
- 验证方式：从日志解码恢复与真值比对
- 依据：[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k06"></a>
## K06 高熵密钥摘要

- 场景：只保存随机256位密钥的SHA256摘要
- 成立条件：真随机输入、密钥无其他暴露、仅研究精确恢复
- 预期：not_recoverable_under_assumptions；摘要/标识泄露可另记
- 配对变化：Base64同一密钥
- 验证方式：API与熵来源核对，不用搜索不到作为不可逆证明
- 依据：[NIST key management](../downloads/papers/NIST-SP800-57pt1r5.pdf)

<a id="k07"></a>
## K07 受保护包装再编码

- 场景：可靠包装后的密文Base64再保存
- 成立条件：KEK材料和解包能力均不可获得，参数正确
- 预期：not_recoverable_under_assumptions；材料不可直接恢复；临时原件另审
- 配对变化：同时保存明文KEK
- 验证方式：解码只能得到密文；跟踪KEK依赖，不得把编码后视为Raw
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)、[HUKS](../downloads/docs/js-apis-huks.md)

<a id="k08"></a>
## K08 密文与KEK同存

- 场景：包装会话密钥，密文和明文KEK同处可读存储
- 成立条件：两份材料完整，算法参数可得
- 预期：recoverable；包装无保密增益
- 配对变化：KEK换为攻击者不可调用的受保护句柄
- 验证方式：独立解包并与原秘密逐字节比较
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k09"></a>
## K09 多层包装

- 场景：K被KEK1包裹，KEK1被KEK2包裹
- 成立条件：最外层KEK2和全部参数可读
- 预期：recoverable；传递恢复依赖
- 配对变化：去掉最终可读KEK根
- 验证方式：按层解包；检测不能只看一跳
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k10"></a>
## K10 包装与Raw合流

- 场景：同一汇点的可行分支分别为Wrapped(K)与Raw(K)
- 成立条件：存在Raw分支，攻击者能触发或may-analysis考虑它
- 预期：possible；可能材料泄露，不得被先到的Wrapped覆盖
- 配对变化：两个分支都为可靠Wrapped
- 验证方式：交换分支/语句顺序，结果一致且保留两种表示
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k11"></a>
## K11 跨域可组合KEK

- 场景：密文在Storage，KEK在Log
- 成立条件：威胁模型明确同一攻击者能读两个域
- 预期：recoverable；跨域组合恢复
- 配对变化：攻击者仅能读一个域
- 验证方式：以攻击者能力集合求可达，不局限同一容器
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k12"></a>
## K12 无根包装循环

- 场景：两个随机密钥互相包装，只有两个密文
- 成立条件：可靠包装、无明文根或解包oracle
- 预期：not_recoverable_under_assumptions；不能凭依赖环凭空恢复
- 配对变化：加入一个明文根
- 验证方式：最小不动点为空；运行不能证明密码学绝对安全
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k13"></a>
## K13 有根包装循环

- 场景：K1与K2相互包装，K1另有可读Raw副本
- 成立条件：明文根和两份密文可得
- 预期：recoverable；循环闭包可达
- 配对变化：去掉明文根
- 验证方式：恢复K1后解包K2，检验求解器传播
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k14"></a>
## K14 包装参数失效

- 场景：辅助函数名为wrap但实现复用GCM nonce或未验证认证
- 成立条件：需按具体算法与攻击目标分析
- 预期：unknown；密码误用成立不自动等于密钥精确可恢复
- 配对变化：可靠参数与认证校验版本
- 验证方式：检查实际实现，不把函数名当净化器
- 依据：[NIST GCM](../downloads/papers/NIST-SP800-38D.pdf)、[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k15"></a>
## K15 同变量多秘密

- 场景：分支将不同生命周期/策略的K1或K2赋给同一变量
- 成立条件：分支条件和秘密身份保留
- 预期：possible；分别按K1/K2策略判定
- 配对变化：两条分支均只使用公开材料
- 验证方式：输出每个身份的路径及策略，不合成单一标签
- 依据：[CryptoFramework](../downloads/docs/js-apis-cryptoFramework.md)

<a id="k16"></a>
## K16 同helper不同上下文

- 场景：encode(iv)与encode(key)调用共享辅助函数
- 成立条件：两个调用目标可解析
- 预期：possible；只在secret对应汇点报材料风险
- 配对变化：helper内联语义等价版本
- 验证方式：检查上下文敏感消融及调用点区分
- 依据：[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k17"></a>
## K17 结构体序列化

- 场景：对象同时含alias与secret字段后JSON序列化
- 成立条件：secret字段实际被序列化并写入可读存储
- 预期：recoverable；字段级材料泄露
- 配对变化：剔除secret字段只保留alias
- 验证方式：解析产物后恢复secret；确认序列化字节表示
- 依据：[CryptoFramework](../downloads/docs/js-apis-cryptoFramework.md)、[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k18"></a>
## K18 external共享清零

- 场景：external_arraybuffer绑定有效Native区域，完整view.fill(0)
- 成立条件：同一区域、字节范围完整、无其他副本、同步时序明确
- 预期：not_recoverable_under_assumptions；该区域在清零后不再含原材料；其他区域另审
- 配对变化：改为buffer_copy
- 验证方式：由Native读回同一区域验证全0，避免只查JS包装对象
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k19"></a>
## K19 副本清零不清原件

- 场景：napi_create_buffer_copy复制后仅清零副本
- 成立条件：Native原件仍存活且可读
- 预期：recoverable；原件残留
- 配对变化：共享external区域后全清零
- 验证方式：分别检查两个地址/长度，验证原件仍匹配
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k20"></a>
## K20 原件清零字符串仍存

- 场景：hex/Base64字符串由Native字节复制后，原件清零
- 成立条件：字符串仍有可达引用且可观察
- 预期：recoverable；不可控字符串副本
- 配对变化：不创建字符串，直接受控buffer使用后清零
- 验证方式：外部真值检查字符串副本；避免任意UTF8可逆假设
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)、[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k21"></a>
## K21 局部view清零

- 场景：TypedArray view只覆盖secret缓冲区部分区间
- 成立条件：字节offset和length已知
- 预期：possible；部分清零，剩余材料可能泄露
- 配对变化：覆盖完整原区域
- 验证方式：比较区间写入，报告部分材料而非必然完整恢复
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k22"></a>
## K22 typedarray输出参数

- 场景：napi_get_typedarray_info取得data后写入/导出秘密
- 成立条件：按API签名解析data=args[4]，区别type/len/offset
- 预期：possible；错误出参建模会丢失秘密传播
- 配对变化：get_arraybuffer_info的args[2]版本
- 验证方式：以C++真实指针别名与JS内容核验
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k23"></a>
## K23 ECDH输出

- 场景：EVP_PKEY_derive实际写入key=args[1]并返回至ArkTS
- 成立条件：调用成功，区分NULL查长度调用
- 预期：possible；返回材料应被建模为派生秘密
- 配对变化：仅查询长度不得产生秘密字节
- 验证方式：独立两端协商校验输出；记录return code
- 依据：[OpenSSL derive](../downloads/docs/openssl-derive.html)、[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k24"></a>
## K24 PBKDF2输出

- 场景：PKCS5_PBKDF2_HMAC写out=args[7]
- 成立条件：固定digest/salt/iterations，成功返回
- 预期：possible；不能误把keylen=args[6]当字节区
- 配对变化：SHA1便捷版本需单独签名
- 验证方式：用官方签名及独立派生结果比对
- 依据：[OpenSSL PBKDF2](../downloads/docs/openssl-pbkdf2.html)

<a id="k25"></a>
## K25 汇点前必经清零

- 场景：所有可行路径在读取同一字节区域前全清零
- 成立条件：无别处副本；清零未优化消除；读取的是清零后内容
- 预期：not_recoverable_under_assumptions；该汇点不包含原秘密
- 配对变化：增加绕过清零的可行分支
- 验证方式：路径/字节区间核对和最终二进制观察
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)、[CWE14](../downloads/docs/cwe14.html)

<a id="k26"></a>
## K26 泄露后清零

- 场景：先记录secret，再对原buffer清零
- 成立条件：日志在清零前已提交且攻击者可读
- 预期：recoverable；清零不能撤回历史泄露
- 配对变化：在日志之前完整清零
- 验证方式：按事件顺序关联sink与kill，检查原始日志
- 依据：[CWE14](../downloads/docs/cwe14.html)

<a id="k27"></a>
## K27 AppStorage内存状态

- 场景：只写AppStorage，不绑定持久化
- 成立条件：仅磁盘读取攻击者，未发生额外落盘
- 预期：not_recoverable_under_assumptions；不能自动报落盘；内存暴露另判
- 配对变化：显式绑定PersistentStorage
- 验证方式：重启/磁盘证据与内存证据分开
- 依据：[AppStorage](../downloads/docs/appstorage.md)

<a id="k28"></a>
## K28 显式持久化绑定

- 场景：可序列化密钥表示经PersistentStorage绑定
- 成立条件：合法API、生命周期触发且持久化完成
- 预期：recoverable；持久化材料泄露
- 配对变化：仅AppStorage无绑定
- 验证方式：实际文件/重启恢复与独立真值比对
- 依据：[PersistentStorage](../downloads/docs/persistentstorage.md)

<a id="k29"></a>
## K29 XML Preferences尚未flush

- 场景：put后在尚未flush的指定观察点取证
- 成立条件：固定XML模式/API版本，未退出或其他隐式持久化
- 预期：unknown；记录缓存意图和实际落盘分别判断
- 配对变化：相同路径await flush成功
- 验证方式：观察时间点前后文件比较，不能仅靠方法名
- 依据：[Preferences](../downloads/docs/preferences.md)

<a id="k30"></a>
## K30 XML Preferences完成flush

- 场景：put完整密钥编码后await flush成功
- 成立条件：攻击者可读取该存储
- 预期：recoverable；持久化风险
- 配对变化：存储仅含alias或可靠包装
- 验证方式：文件解析及解码真值核验
- 依据：[Preferences](../downloads/docs/preferences.md)、[RFC4648](../downloads/docs/rfc4648-base64.txt)

<a id="k31"></a>
## K31 HKDF缺省salt

- 场景：高熵输入使用RFC5869允许的缺省salt
- 成立条件：输入来源和用途满足协议；不把HKDF用于口令加固
- 预期：not_applicable；不能仅凭无随机salt判弱派生
- 配对变化：低熵口令直接作IKM另审
- 验证方式：以RFC5869测试向量/条件核对
- 依据：[RFC5869](../downloads/docs/rfc5869.txt)

<a id="k32"></a>
## K32 GCM计数器nonce

- 场景：同一密钥下nonce计数器唯一，重启不重用
- 成立条件：唯一性覆盖所有调用、设备和重启范围
- 预期：not_applicable；非随机不自动是误用；复用是另一风险
- 配对变化：重启将计数器归零造成同密钥重复
- 验证方式：记录key identity+nonce集合，单独验证重启路径
- 依据：[NIST GCM](../downloads/papers/NIST-SP800-38D.pdf)

<a id="k33"></a>
## K33 低熵秘密摘要

- 场景：小字典口令经SHA256摘要后公开
- 成立条件：攻击者有已知候选空间
- 预期：recoverable；摘要不能消除可枚举风险
- 配对变化：真正高熵256位随机密钥
- 验证方式：限定公开测试字典，独立枚举匹配；不推广到高熵密钥
- 依据：[NIST key management](../downloads/papers/NIST-SP800-57pt1r5.pdf)、[RFC5869](../downloads/docs/rfc5869.txt)

<a id="k34"></a>
## K34 长传播链

- 场景：20层包装函数传递秘密到汇点
- 成立条件：调用路径可达，链长超过实现迭代上限的典型值
- 预期：recoverable；不能因固定轮数提前停止漏报
- 配对变化：1层语义等价链
- 验证方式：比较短/长链结果；记录收敛状态/Unknown
- 依据：[ArkAnalyzer](../downloads/papers/ArkAnalyzer-2501.05798.pdf)

<a id="k35"></a>
## K35 求解顺序不变性

- 场景：交换独立语句/函数声明/分支遍历顺序
- 成立条件：程序可观察语义保持不变
- 预期：possible；结果应保持等价，不受先到事实覆盖
- 配对变化：未变换原例
- 验证方式：对比规范化证据集合，不能仅比告警总数
- 依据：[MASC](../downloads/papers/CryptoDetectors-MASC-2107.07065.pdf)

<a id="k36"></a>
## K36 循环与phi收敛

- 场景：循环传播多种表示并在退出后使用
- 成立条件：CFG与不动点规则明确，保证分析终止策略
- 预期：possible；不能未收敛而默认安全
- 配对变化：无循环展开的等价有限路径
- 验证方式：记录worklist耗尽/迭代截断，截断输出Unknown
- 依据：[ArkAnalyzer](../downloads/papers/ArkAnalyzer-2501.05798.pdf)

<a id="k37"></a>
## K37 路径相关KEK与密文

- 场景：两个互斥分支分别产生不匹配的KEK与密文
- 成立条件：不存在同时可行的匹配材料集合
- 预期：not_recoverable_under_assumptions；路径不敏感may告警应标可能/保守误报
- 配对变化：增加同时可读的匹配分支
- 验证方式：人工执行条件和密钥identity配对核对
- 依据：[RFC3394](../downloads/docs/rfc3394.txt)

<a id="k38"></a>
## K38 同名方法不同符号

- 场景：自定义普通对象也有getEncoded/convertKey等方法
- 成立条件：目标不是密码SDK类型
- 预期：not_applicable；不能按短方法名误标密钥源
- 配对变化：真实cryptoFramework对象同名调用
- 验证方式：使用模块/类型/调用目标身份核验
- 依据：[CryptoFramework](../downloads/docs/js-apis-cryptoFramework.md)

<a id="k39"></a>
## K39 未知Native摘要

- 场景：调用未建模Native方法后将返回值存储
- 成立条件：输入含秘密但无法确定返回关系
- 预期：unknown；未知不能被当成安全净化器
- 配对变化：有完整源码和可信摘要版本
- 验证方式：确认诊断包含未支持边界及传播保守策略
- 依据：[OpenHarmony N-API](../downloads/docs/napi-data-types-interfaces.md)

<a id="k40"></a>
## K40 脱敏日志实参与字符串

- 场景：日志只输出固定标签或公开摘要，secret未成为实参
- 成立条件：确认格式字符串、实参位置与库签名
- 预期：not_applicable；不能因变量名key或log短名就报告材料泄露
- 配对变化：实际将完整secret编码传入日志
- 验证方式：检查真实sink参数与产物，不以关键词代替流证据
- 依据：[CryptoFramework](../downloads/docs/js-apis-cryptoFramework.md)、[RFC4648](../downloads/docs/rfc4648-base64.txt)
