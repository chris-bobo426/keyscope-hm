# 鸿钥卫士 KeyScope-HM v3.0

**面向 HarmonyOS 混合应用的跨运行时密钥表示与暴露风险分析系统**  
*Cross-Runtime Key Representation & Exposure Risk Analysis System for HarmonyOS Hybrid Applications*

从 GitHub 获取完整工程：

```powershell
git clone --recurse-submodules https://github.com/chris-bobo426/keyscope-hm.git
cd keyscope-hm
npm ci
```

8 个上游评测工程通过 Git 子模块固定版本。已有克隆可运行 `git submodule update --init --recursive` 补齐；研究下载副本与公开仓库内容的区别见 [GitHub 仓库说明](docs/GITHUB.md)。

---

## 1. 项目简介与核心架构

**鸿钥卫士（KeyScope-HM v3.0）** 是面向 **HarmonyOS NEXT（ArkTS + Native C/C++ NAPI + HUKS 硬件密钥库）** 混合架构构建的静态密码安全分析系统与交互式编译器中间表示（IR / AST）对照工作台。

针对传统单运行时二元污点分析在鸿蒙混合应用中面临的**“硬件句柄与受控包装密文误报”**、**“跨 NAPI 边界拷贝（Copy）与别名（Alias）清零语义失配”**以及**“软包装密文与明文 KEK 同域共置漏报”**三大痛点，本系统：
1. **形式化模型（LSR）**：提出逻辑秘密身份（$\kappa \in \mathcal{K}$）与物理表示状态（$\rho \in \mathcal{R}$）解耦模型，定义可恢复性全序半格 $\mathsf{OneWay} < \mathsf{Handle} < \mathsf{Wrapped} < \mathsf{KeyObj} < \mathsf{Raw} < \mathsf{Enc}$ 与单调合流并算子 $\sqcup_{\text{form}}$（严格保证多路径事实到达顺序无关性），并通过跟踪 `directCarries` 与 `wrapBy` 确保受控包装密文经二次 Base64/Hex 编码或持久化时不产生误报。
2. **双引擎编译器底座**：
   - **ArkTS 侧**：深度集成 OpenHarmony 官方 `arkanalyzer@1.0.95`，构建 `Scene`、方法控制流图 `Cfg`、三地址 SSA 中间表示（`ArkAssignStmt` / `ArkInvokeStmt` / `ArkReturnStmt`），并实例化运行 `CallGraph`、`PagBuilder` 与自定义 `KeyScopeApakPlugin` 指针分析插件。
   - **Native C/C++ 侧**：通过 Python `ctypes` 真实调用本地 LLVM `libclang.dll`（`clang version 15.0.4`），在内存中解析 C/C++ 翻译单元并遍历真实 Clang AST 游标（`FunctionDecl`、`ParmDecl`、`VarDecl`、`CallExpr`、`ReturnStmt`），按 OpenSSL / HiTLS / HUKS 官方函数签名精确识别输出参数位置（如 `EVP_PKEY_derive` 第 2 参数 `out`、`PKCS5_PBKDF2_HMAC` 第 8 参数、`HITLS_CRYPT_DeriveKey` 第 2 参数），自动生成跨 NAPI 边界的 `copy` vs `alias` 与 `Must-Zeroization` 语义摘要。
3. **交互式编译器 IR / Clang AST / LSR 溯源图可视化分析工作台**：
   - 提供类似 Compiler Explorer (Godbolt) 的**三栏同步对照界面**（**Pane A: ArkTS/C++ 源码 $\leftrightarrow$ Pane B: ArkAnalyzer 三地址 SSA IR & APAK PAG $\leftrightarrow$ Pane C: LLVM libclang 15.0.4 C++ AST & NAPI 摘要**）、**交互式 SVG 跨运行时密钥表示溯源图**与**在线实时沙盒编辑器**。

---

## 2. 如何使用本系统（前端工作台与命令行）

### 方式一：启动交互式编译器 IR / AST / 溯源图 Web 分析工作台（推荐演示使用）
```powershell
npm run ui
```
启动后在浏览器访问 **`http://localhost:3000`**：
- **Tab 1（编译器三地址 IR / libclang AST 对照与在线沙盒）**：可通过顶部下拉框一键切换预置的 `F1`–`F8` 安全/风险配对样本与 8 个真实开源鸿蒙仓库，点击任意源码行即可联动高亮对应的 ArkAnalyzer 三地址 IR 指令与 `libclang 15.0.4` C++ AST 游标节点；点击 **“打开自定义 ArkTS + C++ 实时沙盒编辑器”** 可直接在浏览器中修改或粘贴任意 ArkTS 与 C++ NAPI 代码，点击运行即可实时调用后端 `ArkAnalyzer + libclang.dll` 查看三地址 IR、AST 摘要与 LSR 告警。
- **Tab 2（交互式 LSR 跨运行时密钥表示溯源图 SVG）**：可视化展示 $\kappa \in \mathcal{K}$ 与 $\rho \in \mathcal{R}$ 的有向溯源图，点击节点可查看形式化四元组属性。
- **Tab 3（5 大独立审查反例验证与外部泛化测试）**：展示全部 5 项独立反例的修复机制与回归结果。
- **Tab 4（8 大真实开源鸿蒙仓库审计台）**：展示 19 条真实仓库静态告警及自动提取的真实源码上下文片段（`sourceSnippet`）。
- **Tab 5（64 样本 × 9 方法对比消融矩阵）** 与 **Tab 6（`-O0/-O2` DSE 反汇编 & Win32 `ReadProcessMemory` 四组内存取证实验室 & CBOM）**。

> **离线免服务预览**：若无需在线编译自定义沙盒代码，亦可直接在浏览器中双击打开自包含单页应用文件 [`report/output/keyscope_report.html`](report/output/keyscope_report.html)，同样内置了全部 6 个交互式功能标签页与工程 IR/AST 数据。

### 方式二：命令行扫描任意 HarmonyOS 混合工程
```powershell
# 扫描指定鸿蒙工程目录并输出 HTML 工作台、SARIF 2.1.0 与 CycloneDX 1.6 CBOM 报告
npx tsx core-ts/cli.ts <projectDir> --output-dir report/output

# 扫描 realworld/repos 下全部 8 个真实开源鸿蒙仓库
npx tsx core-ts/cli.ts --all-realworld --output-dir report/output
```

---

## 3. 核心实测与独立反例验证成果

1. **5 大独立审查反例与外部留出泛化测试（Gate G5，100% 通过）**：
   - `wrapped_encoded`：对 `F3_v1_direct_A_Safe` 的 HUKS 包装密文增加 `Base64Helper.encodeToStringSync` 编码并持久化，实测 **0 误报**；而在同域共置明文 KEK 时准确检出 `V2`。
   - `merge_order`：同一存储点按 `["wrapped", "raw"]`、`["raw", "wrapped"]`、`["both"]` 三种顺序到达时，经半格单调并算子 $\sqcup_{\text{form}}$ 合流后一致收敛为 `form = Raw, recoverable = true`。
   - `native_derive_output`：通过 `libclang 15.0.4` 解析 `EVP_PKEY_derive(ctx, out, &len)`，准确将第 2 参数 `out` 识别为秘密输出缓冲区（`creates[0].obj === "out"`）并关联 `napi_create_buffer_copy` 与 `OPENSSL_cleanse`。
   - `file_name_dependency`：所有规则均基于函数体真实语句结构且与文件名无关；空函数在 `huks_napi_common.cpp` 下为 **0 告警**，真实缺陷代码改名为 `arbitrary_renamed_file.cpp` 后检出完全一致的 `E1_M4` 告警。
   - `External Held-Out Suite`：在基准模板之外构造的 `PKCS5_PBKDF2_HMAC`（第 8 参数输出）与 `HITLS_CRYPT_DeriveKey`（第 2 参数输出）跨语言混合样例上取得 100% 准确分类。
2. **64 样本受控配对基准 (`HarmonyKeyRepBench`)**：
   - 覆盖 `F1`–`F8` 八大能力家族（32 个 `A_Safe` + 32 个 `B_Risky`）$\times$ 9 种方法对比消融（共 576 次真实分析）。
   - **KeyScope-HM (Full v3)** 在该自建配对基准上达成 **TP = 32, TN = 32, FP = 0, FN = 0 (F1 = 100.00%, A-FPR = 0.00%)**，中位耗时 **108.25 ms**。
3. **8 个真实开源 OpenHarmony / HarmonyOS 仓库静态扫描（附真实源码证据）**：
   - 扫描 4 个纯 ArkTS 仓库与 4 个 ArkTS + C++ NAPI 混合仓库（共 54 个 ArkTS 文件、495 个 C/C++ 文件），检出 **19 条带真实源码上下文片段 (`sourceSnippet`) 的静态告警**（阴性对照工程 `harmonyos_preferences` 为 **0 告警**），全部持久化于 [`realworld/keyscope_realworld.db`](realworld/keyscope_realworld.db)。
4. **跨层二进制与 Win32 `ReadProcessMemory` 四组对称内存取证验证**：
   - **编译器 DSE 反汇编实验（GCC 13.2 + Objdump）**：证实普通 `memset` 在 `-O2` 优化下被编译器死存储消除（DSE）完全抹除（`hasZeroingCallOrStore = false`），而 `volatile` 擦除指令在 `-O2` 下完整保留。
   - **Win32 `ReadProcessMemory` 四组进程物理内存取证实验（$N=10$ 轮独立子进程）**：彻底移除 `Symbol.for`，由原生 C 程序 [`proc_mem_scanner.c`](dynamic/heap_experiment/proc_mem_scanner.c) 通过 `VirtualQueryEx` + `ReadProcessMemory` 扫描独立子进程私有可读写虚拟内存页：
     - **基线组（Pre-Exec Baseline）**：**0 / 10 (0%)**
     - **正控组（Positive Control：未清零 `Uint8Array` 16B Raw Key）**：**10 / 10 (100%)**（直接证明观测手段可 100% 检出未清零的原始二进制缓冲区）
     - **风险组（Risky Group：不可变 `String` 置空引用 `ref = null`）**：**10 / 10 (100%)**
     - **安全组（Safe Group：`Uint8Array` 调用 `.fill(0)` 原地覆写清零）**：**0 / 10 (0%)**

---

## 4. 官方参赛文档导航

- 📘 [**01_系统设计方案.md**](docs/01_系统设计方案.md)：背景痛点、威胁模型、LSR 形式化定义、半格合流与 `directCarries` 保包装规则、双引擎架构与交互式工作台设计。
- 🧪 [**02_系统测试方案.md**](docs/02_系统测试方案.md)：测试环境、5 大独立反例与外部泛化测试、64 样本 9 方法对比消融、8 个真实开源鸿蒙仓库静态告警与源码证据、`-O0/-O2` DSE 反汇编与四组 `ReadProcessMemory` 内存取证报告。
- 🛠️ [**03_其他文档_基准说明与复现手册.md**](docs/03_其他文档_基准说明与复现手册.md)：工程目录说明、交互式 Web 工作台使用指南、一键复现指令、开源社区修复补丁建议。
- 📜 [**04_参赛作品声明.md**](docs/04_参赛作品声明.md)：原创性声明、开源组件合规边界清单、实验有效性边界与负责任安全研究声明。

---

## 5. 一键复现与验收命令

```powershell
# 一键运行全流程评测、动态取证、报告生成与 G1-G5 五道关口验收（含严格失败即停止检查）
powershell -ExecutionPolicy Bypass -File .\run_all.ps1

# 或分步执行：
npm test                                                    # 执行 G1-G5 五道验收关口 (含 5 大反例与外部泛化测试)
npm run build                                               # TypeScript 全量类型与编译检查
npm run ui                                                  # 启动 http://localhost:3000 交互式编译器 IR/AST 工作台
```
