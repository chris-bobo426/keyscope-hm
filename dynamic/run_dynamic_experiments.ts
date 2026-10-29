/**
 * dynamic/run_dynamic_experiments.ts
 * 鸿钥卫士 KeyScope-HM v3.0 —— 运行时堆内存快照实验 + 编译器死存储消除反汇编对比实验统一入口
 */

import { runDisassemblyExperiment } from './disasm_experiment/run_disasm_experiment';
import { runHeapSnapshotExperiment } from './heap_experiment/run_heap_experiment';

export async function runAllDynamicExperiments() {
  const disasmReport = runDisassemblyExperiment();
  const heapReport = await runHeapSnapshotExperiment(10);
  return { disasmReport, heapReport };
}

if (require.main === module) {
  runAllDynamicExperiments().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
