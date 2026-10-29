import concurrent.futures,hashlib,json,pathlib,re,sys,urllib.parse,urllib.request
from pypdf import PdfReader
sys.stdout.reconfigure(encoding='utf-8')
R=pathlib.Path(__file__).resolve().parents[1];p=R/'news/download-results.json';rows=json.loads(p.read_text(encoding='utf-8'))
x=next(x for x in rows if x['id']=='N052');url=urllib.parse.quote(x['url'],safe=':/?&=%#@+,;');total=26209939;chunk=524288
def get_range(start):
    end=min(start+chunk,total)-1
    req=urllib.request.Request(url,headers={'Range':f'bytes={start}-{end}','User-Agent':'Mozilla/5.0'})
    with urllib.request.urlopen(req,timeout=35) as r:
        cr=r.headers.get('Content-Range','');data=r.read(chunk+1)
        if cr!=f'bytes {start}-{end}/{total}' or len(data)!=end-start+1:raise ValueError(f'range mismatch at {start}: {cr}, {len(data)}')
        return start,data
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:chunks=list(pool.map(get_range,range(0,total,chunk)))
body=b''.join(d for _,d in sorted(chunks));assert len(body)==total
dest=R/'news/articles/N052.pdf';dest.write_bytes(body);reader=PdfReader(dest)
x.update(downloaded=True,content_status='pdf_valid',bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),pdf_pages=len(reader.pages),download_method='validated HTTP ranges, 50 blocks; Content-Range and lengths checked');x.pop('error',None)
p.write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf-8')
print('N052 complete',len(body),'pages',len(reader.pages))
