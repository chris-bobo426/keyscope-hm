import csv,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
# These are proposed research cases, not executed tests or fabricated results.
rows=[
('K01','句柄落盘','F1','仅持久化HUKS别名，不输出密钥材料','存储读取者无应用解密/签名调用权限','not_recoverable_under_assumptions','无材料泄露；句柄能力另审','改为getEncoded().data后编码落盘','检查持久化内容与密钥身份，不将alias字符串当真值','huks'),
('K02','Base64材料落盘','F1','随机对称密钥字节Base64后写XML Preferences并flush','攻击者能读该存储，编码完整','recoverable','明文等价持久化','只保存不可用的alias','外部解码与独立真值逐字节比对','base64,prefs'),
('K03','公钥导出','F1','exportKeyItem导出公钥并保存','确认对象是非对称公钥而非私钥/对称材料','not_applicable','公钥不标作秘密；授权另判','替换为私钥编码路径并单独验证','确认官方API返回类型与密钥种类','huks'),
('K04','公开IV日志','F5','toHex(iv)后记录日志','iv确为公开参数，未复用且不包含秘密','not_applicable','无密钥材料泄露','同一辅助函数接收密钥','参数身份追踪及日志值核对','gcm,base64'),
('K05','密钥日志','F5','toHex(secret)后记录日志','日志读取者可以取得完整hex','recoverable','日志泄露','相同helper仅处理公开IV','从日志解码恢复与真值比对','base64'),
('K06','高熵密钥摘要','F6','只保存随机256位密钥的SHA256摘要','真随机输入、密钥无其他暴露、仅研究精确恢复','not_recoverable_under_assumptions','摘要/标识泄露可另记','Base64同一密钥','API与熵来源核对，不用搜索不到作为不可逆证明','nist'),
('K07','受保护包装再编码','F3','可靠包装后的密文Base64再保存','KEK材料和解包能力均不可获得，参数正确','not_recoverable_under_assumptions','材料不可直接恢复；临时原件另审','同时保存明文KEK','解码只能得到密文；跟踪KEK依赖，不得把编码后视为Raw','wrap,huks'),
('K08','密文与KEK同存','F3','包装会话密钥，密文和明文KEK同处可读存储','两份材料完整，算法参数可得','recoverable','包装无保密增益','KEK换为攻击者不可调用的受保护句柄','独立解包并与原秘密逐字节比较','wrap'),
('K09','多层包装','F3','K被KEK1包裹，KEK1被KEK2包裹','最外层KEK2和全部参数可读','recoverable','传递恢复依赖','去掉最终可读KEK根','按层解包；检测不能只看一跳','wrap'),
('K10','包装与Raw合流','F3','同一汇点的可行分支分别为Wrapped(K)与Raw(K)','存在Raw分支，攻击者能触发或may-analysis考虑它','possible','可能材料泄露，不得被先到的Wrapped覆盖','两个分支都为可靠Wrapped','交换分支/语句顺序，结果一致且保留两种表示','wrap'),
('K11','跨域可组合KEK','F3','密文在Storage，KEK在Log','威胁模型明确同一攻击者能读两个域','recoverable','跨域组合恢复','攻击者仅能读一个域','以攻击者能力集合求可达，不局限同一容器','wrap'),
('K12','无根包装循环','F3','两个随机密钥互相包装，只有两个密文','可靠包装、无明文根或解包oracle','not_recoverable_under_assumptions','不能凭依赖环凭空恢复','加入一个明文根','最小不动点为空；运行不能证明密码学绝对安全','wrap'),
('K13','有根包装循环','F3','K1与K2相互包装，K1另有可读Raw副本','明文根和两份密文可得','recoverable','循环闭包可达','去掉明文根','恢复K1后解包K2，检验求解器传播','wrap'),
('K14','包装参数失效','F3','辅助函数名为wrap但实现复用GCM nonce或未验证认证','需按具体算法与攻击目标分析','unknown','密码误用成立不自动等于密钥精确可恢复','可靠参数与认证校验版本','检查实际实现，不把函数名当净化器','gcm,wrap'),
('K15','同变量多秘密','F4','分支将不同生命周期/策略的K1或K2赋给同一变量','分支条件和秘密身份保留','possible','分别按K1/K2策略判定','两条分支均只使用公开材料','输出每个身份的路径及策略，不合成单一标签','crypto'),
('K16','同helper不同上下文','F5','encode(iv)与encode(key)调用共享辅助函数','两个调用目标可解析','possible','只在secret对应汇点报材料风险','helper内联语义等价版本','检查上下文敏感消融及调用点区分','base64'),
('K17','结构体序列化','F7','对象同时含alias与secret字段后JSON序列化','secret字段实际被序列化并写入可读存储','recoverable','字段级材料泄露','剔除secret字段只保留alias','解析产物后恢复secret；确认序列化字节表示','crypto,base64'),
('K18','external共享清零','F8','external_arraybuffer绑定有效Native区域，完整view.fill(0)','同一区域、字节范围完整、无其他副本、同步时序明确','not_recoverable_under_assumptions','该区域在清零后不再含原材料；其他区域另审','改为buffer_copy','由Native读回同一区域验证全0，避免只查JS包装对象','napi'),
('K19','副本清零不清原件','F8','napi_create_buffer_copy复制后仅清零副本','Native原件仍存活且可读','recoverable','原件残留','共享external区域后全清零','分别检查两个地址/长度，验证原件仍匹配','napi'),
('K20','原件清零字符串仍存','F2','hex/Base64字符串由Native字节复制后，原件清零','字符串仍有可达引用且可观察','recoverable','不可控字符串副本','不创建字符串，直接受控buffer使用后清零','外部真值检查字符串副本；避免任意UTF8可逆假设','napi,base64'),
('K21','局部view清零','F8','TypedArray view只覆盖secret缓冲区部分区间','字节offset和length已知','possible','部分清零，剩余材料可能泄露','覆盖完整原区域','比较区间写入，报告部分材料而非必然完整恢复','napi'),
('K22','typedarray输出参数','F2','napi_get_typedarray_info取得data后写入/导出秘密','按API签名解析data=args[4]，区别type/len/offset','possible','错误出参建模会丢失秘密传播','get_arraybuffer_info的args[2]版本','以C++真实指针别名与JS内容核验','napi'),
('K23','ECDH输出','F2','EVP_PKEY_derive实际写入key=args[1]并返回至ArkTS','调用成功，区分NULL查长度调用','possible','返回材料应被建模为派生秘密','仅查询长度不得产生秘密字节','独立两端协商校验输出；记录return code','derive,napi'),
('K24','PBKDF2输出','F2','PKCS5_PBKDF2_HMAC写out=args[7]','固定digest/salt/iterations，成功返回','possible','不能误把keylen=args[6]当字节区','SHA1便捷版本需单独签名','用官方签名及独立派生结果比对','pbkdf2'),
('K25','汇点前必经清零','F8','所有可行路径在读取同一字节区域前全清零','无别处副本；清零未优化消除；读取的是清零后内容','not_recoverable_under_assumptions','该汇点不包含原秘密','增加绕过清零的可行分支','路径/字节区间核对和最终二进制观察','napi,cwe14'),
('K26','泄露后清零','F8','先记录secret，再对原buffer清零','日志在清零前已提交且攻击者可读','recoverable','清零不能撤回历史泄露','在日志之前完整清零','按事件顺序关联sink与kill，检查原始日志','cwe14'),
('K27','AppStorage内存状态','扩展','只写AppStorage，不绑定持久化','仅磁盘读取攻击者，未发生额外落盘','not_recoverable_under_assumptions','不能自动报落盘；内存暴露另判','显式绑定PersistentStorage','重启/磁盘证据与内存证据分开','appstorage'),
('K28','显式持久化绑定','扩展','可序列化密钥表示经PersistentStorage绑定','合法API、生命周期触发且持久化完成','recoverable','持久化材料泄露','仅AppStorage无绑定','实际文件/重启恢复与独立真值比对','persistent'),
('K29','XML Preferences尚未flush','扩展','put后在尚未flush的指定观察点取证','固定XML模式/API版本，未退出或其他隐式持久化','unknown','记录缓存意图和实际落盘分别判断','相同路径await flush成功','观察时间点前后文件比较，不能仅靠方法名','prefs'),
('K30','XML Preferences完成flush','扩展','put完整密钥编码后await flush成功','攻击者可读取该存储','recoverable','持久化风险','存储仅含alias或可靠包装','文件解析及解码真值核验','prefs,base64'),
('K31','HKDF缺省salt','扩展','高熵输入使用RFC5869允许的缺省salt','输入来源和用途满足协议；不把HKDF用于口令加固','not_applicable','不能仅凭无随机salt判弱派生','低熵口令直接作IKM另审','以RFC5869测试向量/条件核对','hkdf'),
('K32','GCM计数器nonce','扩展','同一密钥下nonce计数器唯一，重启不重用','唯一性覆盖所有调用、设备和重启范围','not_applicable','非随机不自动是误用；复用是另一风险','重启将计数器归零造成同密钥重复','记录key identity+nonce集合，单独验证重启路径','gcm'),
('K33','低熵秘密摘要','F6','小字典口令经SHA256摘要后公开','攻击者有已知候选空间','recoverable','摘要不能消除可枚举风险','真正高熵256位随机密钥','限定公开测试字典，独立枚举匹配；不推广到高熵密钥','nist,hkdf'),
('K34','长传播链','扩展','20层包装函数传递秘密到汇点','调用路径可达，链长超过实现迭代上限的典型值','recoverable','不能因固定轮数提前停止漏报','1层语义等价链','比较短/长链结果；记录收敛状态/Unknown','arkanalyzer'),
('K35','求解顺序不变性','扩展','交换独立语句/函数声明/分支遍历顺序','程序可观察语义保持不变','possible','结果应保持等价，不受先到事实覆盖','未变换原例','对比规范化证据集合，不能仅比告警总数','masc'),
('K36','循环与phi收敛','扩展','循环传播多种表示并在退出后使用','CFG与不动点规则明确，保证分析终止策略','possible','不能未收敛而默认安全','无循环展开的等价有限路径','记录worklist耗尽/迭代截断，截断输出Unknown','arkanalyzer'),
('K37','路径相关KEK与密文','F4','两个互斥分支分别产生不匹配的KEK与密文','不存在同时可行的匹配材料集合','not_recoverable_under_assumptions','路径不敏感may告警应标可能/保守误报','增加同时可读的匹配分支','人工执行条件和密钥identity配对核对','wrap'),
('K38','同名方法不同符号','扩展','自定义普通对象也有getEncoded/convertKey等方法','目标不是密码SDK类型','not_applicable','不能按短方法名误标密钥源','真实cryptoFramework对象同名调用','使用模块/类型/调用目标身份核验','crypto'),
('K39','未知Native摘要','F2','调用未建模Native方法后将返回值存储','输入含秘密但无法确定返回关系','unknown','未知不能被当成安全净化器','有完整源码和可信摘要版本','确认诊断包含未支持边界及传播保守策略','napi'),
('K40','脱敏日志实参与字符串','扩展','日志只输出固定标签或公开摘要，secret未成为实参','确认格式字符串、实参位置与库签名','not_applicable','不能因变量名key或log短名就报告材料泄露','实际将完整secret编码传入日志','检查真实sink参数与产物，不以关键词代替流证据','crypto,base64'),
]
refs={
'huks':('HUKS','downloads/docs/js-apis-huks.md'), 'crypto':('CryptoFramework','downloads/docs/js-apis-cryptoFramework.md'),
'base64':('RFC4648','downloads/docs/rfc4648-base64.txt'), 'prefs':('Preferences','downloads/docs/preferences.md'),
'gcm':('NIST GCM','downloads/papers/NIST-SP800-38D.pdf'), 'nist':('NIST key management','downloads/papers/NIST-SP800-57pt1r5.pdf'),
'wrap':('RFC3394','downloads/docs/rfc3394.txt'), 'napi':('OpenHarmony N-API','downloads/docs/napi-data-types-interfaces.md'),
'derive':('OpenSSL derive','downloads/docs/openssl-derive.html'), 'pbkdf2':('OpenSSL PBKDF2','downloads/docs/openssl-pbkdf2.html'),
'cwe14':('CWE14','downloads/docs/cwe14.html'), 'appstorage':('AppStorage','downloads/docs/appstorage.md'),
'persistent':('PersistentStorage','downloads/docs/persistentstorage.md'), 'hkdf':('RFC5869','downloads/docs/rfc5869.txt'),
'arkanalyzer':('ArkAnalyzer','downloads/papers/ArkAnalyzer-2501.05798.pdf'), 'masc':('MASC','downloads/papers/CryptoDetectors-MASC-2107.07065.pdf')}
cols=['case_id','title','family','scenario','assumptions','expected_recoverability','expected_policy_risk','paired_change','oracle','source_keys']
cases=[]
for row in rows:
    d=dict(zip(cols,row));d['status']='proposed_not_executed';d['source_paths']=[refs[k][1] for k in d['source_keys'].split(',')];cases.append(d)
out=ROOT/'examples';out.mkdir(exist_ok=True)
(out/'cases.json').write_text(json.dumps({'version':'2026-10-29','label_status':'hypotheses_pending_independent_validation','cases':cases},ensure_ascii=False,indent=2),encoding='utf-8')
with (out/'cases.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=cols+['status']);w.writeheader();w.writerows({k:v for k,v in c.items() if k!='source_paths'} for c in cases)
lines=['# 40个待验证场景','', '状态：全部为设计假设，尚未作为本资料包中的实验执行。`possible`表示条件分支下可能；`unknown`表示现有信息不足；`not_applicable`表示该对象/条件不属于密钥恢复阳性。负例只在列出的假设下成立。','', '| ID | 场景 | F族 | 预期恢复分类 |','|---|---|---|---|']
lines += [f"| [{c['case_id']}](#{c['case_id'].lower()}) | {c['title']} | {c['family']} | {c['expected_recoverability']} |" for c in cases]
for c in cases:
    lines += ['',f"<a id=\"{c['case_id'].lower()}\"></a>",f"## {c['case_id']} {c['title']}",'',f"- 场景：{c['scenario']}",f"- 成立条件：{c['assumptions']}",f"- 预期：{c['expected_recoverability']}；{c['expected_policy_risk']}",f"- 配对变化：{c['paired_change']}",f"- 验证方式：{c['oracle']}",'- 依据：'+'、'.join(f'[{refs[k][0]}](../{refs[k][1]})' for k in c['source_keys'].split(','))]
(out/'cases.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
fields=['case_id','source_ref','source_commit','source_sha256','sdk','api_level','device','system_build','threat_model','secret_identity','entrypoint','path_condition','expected_recoverability','expected_policy_risk','expected_flow','expected_zeroized_regions','oracle','label_author','review_status','build_status','run_status','notes']
with (out/'ground-truth-template.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerow({'case_id':'TO_FILL','review_status':'pending','build_status':'not_run','run_status':'not_run'})
template={'schema_version':1,'status':'template_not_executed','run_id':None,'case_id':None,'source_commit':None,'source_sha256':None,'manifest_sha256':None,'platform':None,'device':None,'system_build':None,'security_patch':None,'sdk':None,'ndk':None,'compiler':None,'optimization_flags':None,'analyzer_version':None,'baseline_or_ablation':None,'command':None,'started_at':None,'exit_code':None,'timeout':None,'parse_errors':None,'unknown_calls':None,'converged':None,'runtime_ms':None,'peak_memory_mb':None,'ground_truth_version':None,'predicted_labels':None,'raw_artifacts':[],'dynamic':{'fresh_process':None,'oracle_outside_target':None,'gc_requested':None,'gc_confirmed':None,'snapshot_scope':None,'positive_control_passed':None,'trial_count':None,'valid_trials':None,'errors':None,'hits':None}}
(out/'run-template.json').write_text(json.dumps(template,ensure_ascii=False,indent=2),encoding='utf-8')
print('Created 40 proposed cases and blank evidence templates')
