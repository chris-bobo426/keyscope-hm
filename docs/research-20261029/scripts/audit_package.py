import csv,datetime,hashlib,json,pathlib,re,urllib.parse,sys
sys.stdout.reconfigure(encoding='utf-8')
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=json.loads((ROOT/'sources/source-index.json').read_text(encoding='utf-8'))
validation=json.loads((ROOT/'sources/collection-validation.json').read_text(encoding='utf-8'))
integrity=json.loads((ROOT/'sources/upstream-integrity.json').read_text(encoding='utf-8'))
cases=json.loads((ROOT/'examples/cases.json').read_text(encoding='utf-8'))['cases']
news=json.loads((ROOT/'news/download-results.json').read_text(encoding='utf-8'))
from pypdf import PdfReader
news_errors=[];news_pdfs=[]
for x in news:
    p=ROOT/x['file']
    if hashlib.sha256(p.read_bytes()).hexdigest()!=x['sha256']:news_errors.append(x['file'])
    if x.get('text_file') and hashlib.sha256((ROOT/x['text_file']).read_bytes()).hexdigest()!=x['text_sha256']:news_errors.append(x['text_file'])
    if x['content_status']=='pdf_valid':news_pdfs.append({'id':x['id'],'pages':len(PdfReader(p).pages)})
assert len(news)==88 and len({x['url'] for x in news})==88
hash_errors=[]
for x in source:
    if x['sha256'] and hashlib.sha256((ROOT/x['file']).read_bytes()).hexdigest()!=x['sha256']:
        hash_errors.append(x['file'])
assert len(cases)==40 and len({x['case_id'] for x in cases})==40
assert all(x['status']=='proposed_not_executed' for x in cases)
for c in cases:
    for p in c['source_paths']:assert (ROOT/p).exists(),p
sample_files=sum(x['files'] for x in validation['official_samples'])
report='''# 完整性检查

检查时间：2026-10-29。此页检查资料包的完整性，不检查分析器正确性或样例执行结果。

| 项目 | 结果 |
|---|---|
| 首批实验资料PDF | 14份：10篇研究论文、1份安全白皮书、3份NIST文档；全部PDF头与页数解析通过 |
| 新闻扩展PDF | 新增6份，233页；完整文件可解析。全包共20份PDF |
| 新闻与宣讲 | 88条独立来源，8个主题；73条网页正文、1条浏览器核实的正文/课件目录、6份PDF、8条页面壳/入口。课件目录中的8份PDF下载要求登录，尚未取得 |
| 代码/发布包 | 5个ZIP的CRC检查通过；1个npm TGZ可读且SHA-512与registry一致 |
| JScamd归档 | 与Zenodo公布的MD5一致；另记录本地SHA-256 |
| 官方样例 | Crypto 49、HUKS 47、N-API 42，共138个文件；三个子树均未截断且Git blob hash全部一致 |
| 验证场景 | 40个唯一ID；全部为待验证假设，无伪造运行结果 |
| 首批实验资料索引 | 225个目标文件记录，221个已下载；其中3个页面壳/错误页明确排除为正文依据，4个目标仍未下载。新闻扩展另见[新闻索引](news/新闻索引.md) |
| 本地交叉引用 | 检查本次编写的Markdown与案例引用；上游仓库原README链接保持原样，不纳入本包链接验收 |
| 完整文件清单 | [SHA256SUMS.csv](SHA256SUMS.csv)，覆盖本资料包所有文件（清单自身除外） |

原始校验：[PDF/归档/样例](sources/collection-validation.json)、[发布者校验值](sources/upstream-integrity.json)、[最终检查](sources/final-audit.json)。未执行任何下载项目的安装、构建、测试脚本或HAP。部分官方样例依赖旧SDK；归档可读取不等于工程可在当前机器运行。

## 整理脚本

- `fetch_sources.py`：按下载计划获取公开文件，记录状态与hash；不执行下载内容。
- `inspect_collection.py`：PDF解析、ZIP CRC、指定小型归档安全解压、官方子树hash检查。
- `build_cases.py`：生成场景表和空白记录模板。
- `build_source_index.py`：合并下载记录，识别已知无效页面，生成来源索引并核对上游hash。
- `audit_package.py`：复核本地链接和hash，生成完整性记录与文件清单。

仅在需要重新整理时运行本目录脚本；不要运行下载仓库里的脚本来“检查压缩包”。所有下载失败与替代来源见 [08](08-获取缺口与证据边界.md)。
'''
(ROOT/'09-完整性检查.md').write_text(report,encoding='utf-8')
link_errors=[];checked=0
docs=list(ROOT.glob('*.md'))+list((ROOT/'news').glob('*.md'))+[ROOT/'examples/cases.md',ROOT/'sources/资料索引.md']
for p in docs:
    content=p.read_text(encoding='utf-8')
    for dest in re.findall(r'\]\(([^)]+)\)',content):
        if dest.startswith(('http://','https://','#','mailto:')):continue
        dest=urllib.parse.unquote(dest.split('#')[0].strip('<>'))
        if dest in ('SHA256SUMS.csv','sources/final-audit.json'):continue
        checked+=1
        if not (p.parent/dest).exists():link_errors.append({'file':str(p.relative_to(ROOT)),'target':dest})
audit={'checked_at':datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),'source_hash_errors':hash_errors,'local_links_checked':checked,'broken_local_links':link_errors,'case_count':len(cases),'all_cases_not_executed':True,'official_sample_files':sample_files,'official_sample_hashes_pass':all(not x['missing'] and not x['hash_mismatch'] and not x['truncated'] for x in validation['official_samples']),'pdf_count':len(validation['pdfs']),'all_pdf_parse_pass':all(x['valid_pdf'] for x in validation['pdfs']),'zip_crc_pass':all(x.get('crc_error') is None for x in validation['archives']),'npm_upstream_integrity_match':integrity['npm_arkanalyzer_1_0_95_integrity_match'],'zenodo_upstream_integrity_match':integrity['zenodo_jscamd_checksum_match'],'known_unusable_http_success':integrity['unusable_content'],'known_missing_downloads':integrity['failed_missing']}
audit.update(news_source_count=len(news),news_hash_errors=news_errors,news_pdf_validation=news_pdfs,news_thin_pages=[x['id'] for x in news if x['content_status']=='thin_or_spa_page_search_evidence_only'],news_attachments_require_login=['N007'],all_pdf_count=len(validation['pdfs'])+len(news_pdfs))
audit['passed']=not hash_errors and not news_errors and not link_errors and audit['official_sample_hashes_pass'] and audit['all_pdf_parse_pass'] and audit['zip_crc_pass'] and audit['npm_upstream_integrity_match'] and audit['zenodo_upstream_integrity_match']
(ROOT/'sources/final-audit.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2),encoding='utf-8')
files=[p for p in sorted(ROOT.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.csv']
with (ROOT/'SHA256SUMS.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.writer(f);w.writerow(['path','bytes','sha256'])
    for p in files:
        data=p.read_bytes();w.writerow([p.relative_to(ROOT).as_posix(),len(data),hashlib.sha256(data).hexdigest()])
print(json.dumps(audit,ensure_ascii=False,indent=2));print('manifest_files',len(files),'bytes',sum(p.stat().st_size for p in files))
if not audit['passed']:raise SystemExit(1)
