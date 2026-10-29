"""Download curated public news/documents; no external source code is executed."""
import concurrent.futures,csv,datetime,hashlib,html,json,pathlib,re,sys,urllib.parse,urllib.request
from html.parser import HTMLParser
sys.stdout.reconfigure(encoding='utf-8')
ROOT=pathlib.Path(__file__).resolve().parents[1];N=ROOT/'news'
candidates=json.loads((N/'candidate-expanded.json').read_text(encoding='utf-8'))
class Plain(HTMLParser):
    def __init__(self):super().__init__();self.parts=[];self.skip=0
    def handle_starttag(self,t,a):
        if t in ('script','style','noscript'):self.skip+=1
        if t in ('p','div','h1','h2','h3','tr','li','br'):self.parts.append('\n')
    def handle_endtag(self,t):
        if t in ('script','style','noscript') and self.skip:self.skip-=1
    def handle_data(self,d):
        if not self.skip:self.parts.append(d)
def canonical(u):
    p=urllib.parse.urlsplit(u)
    q=urllib.parse.parse_qsl(p.query,keep_blank_values=True)
    q=[(k,v) for k,v in q if not (k in ('trk','cst','ha_source','ha_sourceId','source') or k.startswith('query-cdbd'))]
    return urllib.parse.urlunsplit((p.scheme,p.netloc,p.path,urllib.parse.urlencode(q),''))
with (N/'curation.tsv').open(encoding='utf-8') as f:rows=list(csv.DictReader(f,delimiter='|'))
selected=[]
for i,row in enumerate(rows,1):
    sel=row.pop('selector')
    if sel=='/implementing-post-quantum-cryptography-in-android/':sel=sel[1:]
    hits=[x for x in candidates if sel in x['url']]
    if not hits and not sel.startswith('https://'):raise ValueError('No observed source for '+sel)
    candidate=hits[0] if hits else {'url':sel,'title':row['title'],'summary':'Direct primary URL verified in web opening or official download link.'}
    row.update(id=f'N{i:03d}',url=canonical(candidate['url']),source_title=candidate['title'],search_evidence=candidate['summary'],selection_basis='curated_from_primary_sources; inspiration_and_test_question_are_our_inferences',verification='source_statement_not_independent_product_test')
    selected.append(row)
urls=[x['url'] for x in selected]
assert len(urls)==len(set(urls)), 'duplicate selected source URL'
(N/'selection.json').write_text(json.dumps(selected,ensure_ascii=False,indent=2),encoding='utf-8')
def fetch(row):
    r=dict(row);r['accessed_at']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
    ispdf=urllib.parse.unquote(r['url']).lower().endswith('.pdf')
    dest=N/'articles'/(r['id']+('.pdf' if ispdf else '.html'));dest.parent.mkdir(exist_ok=True)
    try:
        req=urllib.request.Request(urllib.parse.quote(r['url'],safe=':/?&=%#@+,;'),headers={'User-Agent':'Mozilla/5.0 (compatible; ResearchArchive/1.0)','Accept':'*/*'})
        with urllib.request.urlopen(req,timeout=35) as res:
            data=res.read(60*1024*1024+1);r.update(http_status=res.status,final_url=res.url,content_type=res.headers.get('Content-Type',''))
        if len(data)>60*1024*1024:raise ValueError('above per-file bound')
        dest.write_bytes(data);r.update(downloaded=True,file=dest.relative_to(ROOT).as_posix(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        if data.startswith(b'%PDF-'):
            from pypdf import PdfReader
            reader=PdfReader(dest);r['pdf_pages']=len(reader.pages);r['content_status']='pdf_valid'
        else:
            raw=data.decode('utf-8',errors='replace');parser=Plain();parser.feed(raw)
            text=re.sub(r'\n\s*\n','\n',''.join(parser.parts)).strip()
            txt=dest.with_suffix('.txt');txt.write_text(text,encoding='utf-8');r['text_file']=txt.relative_to(ROOT).as_posix();r['text_chars']=len(text)
            title=re.search(r'<title[^>]*>(.*?)</title>',raw,flags=re.S|re.I)
            r['downloaded_page_title']=html.unescape(re.sub('<[^>]+>','',title.group(1))).strip() if title else ''
            r['content_status']='html_body_saved_needs_scope_check' if len(text)>600 else 'thin_or_spa_page_search_evidence_only'
            if re.search(r'404|Access Denied|Just a moment|Request Rejected',r['downloaded_page_title'],re.I):r['content_status']='access_or_wrong_page'
            tokens=[t for t in re.split(r'\s+|[：:，,·—|]',r['title']) if len(t)>=4]
            r['title_hint_found']=any(t in text for t in tokens)
        return r
    except Exception as exc:
        r.update(downloaded=False,content_status='download_failed_search_evidence_only',error=str(exc));return r
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    results=list(pool.map(fetch,selected))
(N/'download-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print('selected',len(results),'downloaded',sum(x['downloaded'] for x in results))
for r in results:
    print(json.dumps({k:r[k] for k in ('id','downloaded','content_status','text_chars','pdf_pages','error') if k in r},ensure_ascii=False))
