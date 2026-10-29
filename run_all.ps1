# run_all.ps1
# 鸿钥卫士 KeyScope-HM v3.0 —— 一键全流程评测、动态取证验证、交互式工作台生成与五道关口验收脚本
# 具备严格失败即停止 ($LASTEXITCODE != 0 立即退出) 保证

$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  鸿钥卫士 KeyScope-HM v3.0 — 一键全量复现与五道关口 (G1-G5) 验收流水线" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

Write-Host "`n[1/6] 运行 64 样本配对基准 (HarmonyKeyRepBench) × 9 方法对比与消融实验..." -ForegroundColor Yellow
npx.cmd tsx eval/run_benchmark_eval.ts
if ($LASTEXITCODE -ne 0) { Write-Error "Step 1 (Benchmark Eval) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n[2/6] 运行 8 个真实开源鸿蒙仓库扫描、真实源码片段提取与 SQLite 入库 (Filename-Agnostic)..." -ForegroundColor Yellow
npx.cmd tsx realworld/run_realworld_scan.ts
if ($LASTEXITCODE -ne 0) { Write-Error "Step 2 (Realworld Scan) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n[3/6] 运行编译器 (-O0 vs -O2) DSE 反汇编与 Win32 ReadProcessMemory 四组内存取证实验 (含未清零 Buffer 正控)..." -ForegroundColor Yellow
npx.cmd tsx dynamic/run_dynamic_experiments.ts
if ($LASTEXITCODE -ne 0) { Write-Error "Step 3 (Dynamic Experiments) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n[4/6] 生成交互式编译器 IR/AST/溯源图 HTML 工作台、OASIS SARIF 2.1.0 与 CycloneDX 1.6 CBOM 报告..." -ForegroundColor Yellow
npx.cmd tsx core-ts/cli.ts --all-realworld --output-dir report/output
if ($LASTEXITCODE -ne 0) { Write-Error "Step 4 (CLI & Report Generation) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n[5/6] 验证交互式 Web 分析工作台服务 (core-ts/server.ts)..." -ForegroundColor Yellow
npx.cmd tsx core-ts/server.ts --check --port 3899
if ($LASTEXITCODE -ne 0) { Write-Error "Step 5 (Workbench Server Check) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n[6/6] 执行 G1-G5 五道验收关口 (含 5 大独立反例与外部泛化测试) 与 TypeScript 编译检查..." -ForegroundColor Yellow
npm.cmd test
if ($LASTEXITCODE -ne 0) { Write-Error "Step 6a (npm test G1-G5) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }
npm.cmd run build
if ($LASTEXITCODE -ne 0) { Write-Error "Step 6b (npm run build) failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }

Write-Host "`n================================================================================" -ForegroundColor Green
Write-Host "  KeyScope-HM v3.0 全部实验、数据库、交互式工作台与 G1-G5 验收关口均已 100% 验证通过！" -ForegroundColor Green
Write-Host "  - 启动交互式编译器 IR/AST 工作台服务: npm run ui (访问 http://localhost:3000)" -ForegroundColor Green
Write-Host "  - 或直接在浏览器打开静态自包含工作台: report/output/keyscope_report.html" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
