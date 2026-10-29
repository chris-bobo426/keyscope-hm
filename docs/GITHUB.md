# GitHub 仓库说明

本仓库包含 KeyScope-HM 源码、合成基准、规则模型、研究文档、资料索引，以及项目目录中已有的评测记录和报告。

## 获取完整工程

```powershell
git clone --recurse-submodules https://github.com/chris-bobo426/keyscope-hm.git
cd keyscope-hm
npm ci
```

若已经使用普通 `git clone` 下载：

```powershell
git submodule update --init --recursive
```

`realworld/repos/` 中的 8 个上游测试工程以 Git 子模块保存，版本固定到本地已有的提交；各项目继续使用其自己的许可证。下载 GitHub ZIP 不包含这些子模块的源码，运行真实项目扫描前需要获取子模块。

## 本地文件与公开仓库

`.gitignore` 排除依赖安装目录、编译缓存、本机配置、环境变量文件及研究资料的下载副本。源码、现有结果文件和 `report/output/` 中的演示报告保留在仓库中。

以下目录的下载副本只保留在原本地工作区：

- `docs/research-20261029/downloads/`
- `docs/research-20261029/news/articles/`

研究文档中指向这些本地副本的链接需要下载资料后使用；原始来源、获取记录和哈希保存在 `docs/research-20261029/sources/`、新闻索引及 `SHA256SUMS.csv` 中，获取脚本保存在 `docs/research-20261029/scripts/` 中。

发布时保留项目现有实验记录和说明；上传操作本身不代表重新运行或独立复核这些实验。
