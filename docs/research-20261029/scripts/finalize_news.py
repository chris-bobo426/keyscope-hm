"""Finalize the curated news archive; never execute downloaded content."""
import collections,csv,datetime,hashlib,html,json,pathlib,re,shutil,sys,urllib.request,urllib.parse
from html.parser import HTMLParser
from pypdf import PdfReader
sys.stdout.reconfigure(encoding='utf-8')
ROOT=pathlib.Path(__file__).resolve().parents[1];N=ROOT/'news'
rows=json.loads((N/'download-results.json').read_text(encoding='utf-8'))
byid={r['id']:r for r in rows}
class Plain(HTMLParser):
    def __init__(self):super().__init__();self.parts=[];self.skip=0
    def handle_starttag(self,t,a):
        if t in ('script','style','noscript'):self.skip+=1
        if t in ('p','div','h1','h2','h3','tr','li','br'):self.parts.append('\n')
    def handle_endtag(self,t):
        if t in ('script','style','noscript') and self.skip:self.skip-=1
    def handle_data(self,d):
        if not self.skip:self.parts.append(d)
def parse_html(r,path):
    data=path.read_bytes();raw=data.decode('utf-8',errors='replace');p=Plain();p.feed(raw)
    txt=re.sub(r'\n\s*\n','\n',''.join(p.parts)).strip();tp=path.with_suffix('.txt');tp.write_text(txt,encoding='utf-8')
    title=re.search(r'<title[^>]*>(.*?)</title>',raw,re.S|re.I)
    r.update(downloaded=True,file=path.relative_to(ROOT).as_posix(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),text_file=tp.relative_to(ROOT).as_posix(),text_chars=len(txt),downloaded_page_title=html.unescape(title.group(1)).strip() if title else '',content_status='html_body_saved_needs_scope_check')
    r.pop('error',None)
dates={'N030':'2026-05-28','N033':'2026-06-26','N055':'2026-05-12','N059':'2026-02-27','N061':'2026-06-08','N071':'2026-05-25','N077':'2026-10-07','N080':'2026-10-15'}
for i,d in dates.items():byid[i]['date_note']=d
parse_html(byid['N040'],N/'articles/N040.html')
byid['N040'].update(http_status=200,final_url=byid['N040']['url'],acquisition_note='Python TLS failed; retrieved with curl using normal certificate verification.')
byid['N083']['content_status']='html_short_notice_body_saved'
byid['N052']['text_extraction_note']='字体编码导致抽取文本乱码，请阅读PDF原件；未完成OCR。'
byid['N007'].update(content_status='browser_body_saved_attachments_require_login',browser_evidence='news/articles/N007-browser-observation.txt',acquisition_note='Browser rendered article and eight attachment names. Clicking download displayed a sign-in prompt; attachment PDFs were not downloaded.')
updates={
 'N084':dict(url='https://cloud.tencent.com/product/events/detail/7209',title='腾讯云Codebuddy Security：静态分析与AI安全Agent联合审计',date_note='2026-07-28',kind='产品发布页',fact='官方宣布静态分析与AI安全Agent联合审计，包含威胁建模、验证与修复环节。',inspiration='仅叠加LLM与静态规则已有产品先例，应证明密钥身份与表示模型的具体增益。',test_question='同一数据集上，表示感知分析相对一般规则和LLM审查增加了哪些可复核发现？'),
 'N085':dict(url='https://cloud.tencent.com/product/events/article/202603',title='腾讯云iOA AI安全中心与凭据盗取防护更新',date_note='功能更新2026-04-15；四月刊标2026年第3期，URL含202603',kind='产品动态',fact='产品月刊记录AI资产盘点、Skill检测、运行防护、沙箱及凭据盗取防护更新。',inspiration='端侧密钥审计可服务于Agent凭据治理，但需区分静态发现与运行时阻断。',test_question='静态发现的凭据流能否与一次可记录的Skill调用及授权主体对应？')}
for i,u in updates.items():
    r=byid[i]
    if r['url']!=u['url']:
        backup=N/'secondary-leads';backup.mkdir(exist_ok=True)
        (backup/(i+'-previous.json')).write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding='utf-8')
        for key in ('file','text_file'):
            if r.get(key):shutil.copy2(ROOT/r[key],backup/(i+'-previous'+pathlib.Path(r[key]).suffix))
        req=urllib.request.Request(u['url'],headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req,timeout=30) as response:
            data=response.read(8*1024*1024);r.update(http_status=response.status,final_url=response.url)
        path=N/'articles'/(i+'.html');path.write_bytes(data);parse_html(r,path)
    r.update(u);r['source_title']=r['downloaded_page_title'];r['search_evidence']='Primary product page opened and checked; archived full public HTML. Earlier community lead retained separately.'
    r['accessed_at']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
for r in rows:
    r['publisher_host']=urllib.parse.urlparse(r['url']).netloc
    if r['content_status']=='pdf_valid':
        reader=PdfReader(ROOT/r['file']);r['pdf_pages']=len(reader.pages);r['archive_label']='PDF完整，已解析页数；文本抽取可能不保留图表/字体'
        tp=(ROOT/r['file']).with_suffix('.txt')
        if not tp.exists():tp.write_text('\n\n'.join('--- Page '+str(i+1)+' ---\n'+(p.extract_text() or '') for i,p in enumerate(reader.pages)),encoding='utf-8')
        r['text_file']=tp.relative_to(ROOT).as_posix();r['text_chars']=len(tp.read_text(encoding='utf-8'))
    elif r['content_status']=='thin_or_spa_page_search_evidence_only':r['archive_label']='页面壳/入口；仅有检索摘要依据，未取得完整正文'
    elif r['content_status']=='browser_body_saved_attachments_require_login':r['archive_label']='浏览器已核实正文与课件目录；附件下载要求登录，未取得PDF'
    elif r.get('downloaded'):r['archive_label']='网页正文已存；厂商陈述不等于独立实测'
    else:r['archive_label']='未下载正文，仅留检索线索'
    if r.get('text_file'):r['text_sha256']=hashlib.sha256((ROOT/r['text_file']).read_bytes()).hexdigest()
assert len(rows)==88 and len({r['url'] for r in rows})==88
(N/'download-results.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
(N/'新闻索引.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
fields=['id','title','theme','kind','date_note','publisher_host','fact','inspiration','test_question','priority','url','archive_label','file','text_file','pdf_pages','bytes','sha256']
with (N/'新闻索引.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
themes=collections.Counter(r['theme'] for r in rows);kinds=collections.Counter(r['kind'] for r in rows)
pdf=[r for r in rows if r['content_status']=='pdf_valid'];thin=[r for r in rows if r['content_status']=='thin_or_spa_page_search_evidence_only']
md=['# 新闻、宣讲与技术动向索引','', '检索截止：2026-10-29。共88条独立来源记录，不等于88起独立事件；同一发布的报道、产品说明与原件分别标注。近期动态以2026年为主，2024—2025年材料保留作背景。','', '每条分为“来源事实”和“我们的启发/待验证问题”。A=优先阅读、与现有研究直接相连；B=可扩展方向；C=背景，不代表质量评分。','', '[返回导航](README.md) · [CSV筛选表](新闻索引.csv) · [JSON完整记录](新闻索引.json) · [12个选题方向](启发与选题地图.md)','']
for theme in themes:
    md+=['## '+theme,'']
    for r in rows:
        md+=['### '+r['id']+' '+r['title'],'',f"- 日期：{r['date_note']}；类型：{r['kind']}；阅读优先级：{r['priority']}。",f"- 原始来源：[{r['source_title']}]({r['url']})。",f"- 来源事实：{r['fact']}",f"- 我们的启发：{r['inspiration']}",f"- 待验证问题：{r['test_question']}",f"- 归档状态：{r['archive_label']}。"]
        if r.get('file'):md+=[f"- 本地：[原件]({pathlib.Path(r['file']).relative_to('news').as_posix()})"+(f" / [提取文本]({pathlib.Path(r['text_file']).relative_to('news').as_posix()})" if r.get('text_file') else f"；{r['pdf_pages']}页")+'。']
        if r.get('browser_evidence'):md+=[f"- [浏览器核对记录]({pathlib.Path(r['browser_evidence']).relative_to('news').as_posix()})。"]
        md+=['']
(N/'新闻索引.md').write_text('\n'.join(md),encoding='utf-8')
readme=['# 面向选题启发的新闻与宣讲资料库','', '截至2026-10-29，共筛选88条来源，覆盖8个主题。范围包括大会宣讲、新闻发布、产品更新、行业案例、技术博客、标准动态及白皮书；不把所有条目混称为新闻，也不将厂商宣传当作验证结果。','', '## 先读什么','', '- [完整新闻索引](新闻索引.md)：逐条查看事件、日期、原文、启发和实验问题。','- [可筛选CSV](新闻索引.csv)：按主题、时间、优先级和资料类型排序。','- [12个选题方向](启发与选题地图.md)：从新闻转化为可以动手验证的问题。','- [华为宣讲与资料入口](华为宣讲与资料入口.md)：专题课件、回放与已下载原件。','- [下载状态与缺口](下载状态与缺口.md)：区分正文、页面壳、课件线索和报告全文。','- [实验准备总包](../README.md)：论文、代码样例、40个待验证场景和实验门槛。','', '## 覆盖分布','', '| 主题 | 条数 |','|---|---:|']
readme += [f'| {t} | {c} |' for t,c in themes.items()]
readme += ['', '涉及华为终端、华为云、OpenHarmony生态，以及Google/Android、Apple、Microsoft、AWS、Anthropic、腾讯、阿里、Samsung、OWASP、NIST、FIDO、GitHub等来源。检索候选包含重复与不相关结果，未将候选数量冒充已完成调研数量。','', '## 获取结果','',f'- 88条均保存了原始响应文件；其中73条保存网页正文、1条经浏览器核实正文与课件目录、{len(pdf)}份为可解析PDF，另{len(thin)}条只有页面壳/入口，不能视为全文归档。','- 6份PDF共'+str(sum(r['pdf_pages'] for r in pdf))+'页；包括鸿蒙智能、云安全、算力基础设施、AI治理、数据治理和应用市场报告。','- HDC专题列出的8份课件仍是待取得的附件线索；已保存名称和公开入口。视频为回放链接，未声称已下载视频文件。','- 每份原件记录URL、访问时间、大小和SHA-256；正文提取仅供检索，图表排版请看PDF原件。N052文本因字体编码而乱码，尚未OCR，应直接阅读PDF。','', '## 推荐阅读顺序','', 'N001 → N007 → N017 → N028 → N044 → N052 → N056 → N065 → N068 → N076 → N079 → N084。先了解场景变化，再考虑是否值得扩展项目；不需要将所有热点做成作品功能。','', '## 资料类型统计','', '| 类型 | 条数 |','|---|---:|']
readme += [f'| {k} | {v} |' for k,v in kinds.items()]
(N/'README.md').write_text('\n'.join(readme)+'\n',encoding='utf-8')
gap=['# 下载状态与缺口','', '检索日：2026-10-29。HTTP成功只证明收到响应，不证明得到正文。','', '## 当前仅有页面壳或入口','', '| ID | 内容 | 原始入口 |','|---|---|']
gap += [f"| {r['id']} | {r['title']} | [来源]({r['url']}) |" for r in thin]
gap += ['', '这些条目保留检索服务返回的标题/摘要及搜索记录，完整正文尚未取得。N078是报告入口，不能声称获取了报告全文。N007另经浏览器核实正文与8份附件目录；点击下载后出现登录提示，故课件未下载，不能引用其内部图表或结论。','', '## 已修复的获取问题','', '- N052正文抽取受字体编码影响产生乱码，未完成OCR；原PDF完整，不据乱码文本推断技术细节。', '- N040：Python TLS失败后以curl正常校验证书取得政府官网页面。','- N052：服务器初次只返回部分字节，之后按Content-Range补齐全部26,209,939字节，完整PDF解析为51页。初次片段未充当完整PDF。','- N084/N085：用腾讯云官方产品发布页替换社区二手转载；原线索留在secondary-leads目录，仅作为检索过程。','', '## 日期与证据解释','', '- 区分事件发生日、文章发布日期、文档更新日、报告覆盖年度和访问日；没有明确日期时保留待核标记。','- 同一发布可能有新闻、产品页、报告原件，88条是来源记录数，不能累加为88个事件或独立佐证。','- 本次未测试这些厂商产品的安全能力，未将公开安全公告推断为当前项目存在相同漏洞。','- 已下载网页存在导航、推荐条目等内容；结论只对应选定新闻/功能段落，不按全页最大日期推定文章时间。','', '原始元数据见[下载记录](download-results.json)，检索过程在search目录，原件在articles目录。']
(N/'下载状态与缺口.md').write_text('\n'.join(gap)+'\n',encoding='utf-8')
print(json.dumps({'sources':len(rows),'themes':themes,'html_bodies':len(rows)-len(pdf)-len(thin),'pdfs':len(pdf),'pdf_pages':sum(r['pdf_pages'] for r in pdf),'thin_pages':len(thin)},ensure_ascii=False))
