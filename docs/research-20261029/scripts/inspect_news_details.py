import json,pathlib,re,sys,urllib.parse,urllib.request
sys.stdout.reconfigure(encoding='utf-8')
R=pathlib.Path(__file__).resolve().parents[1]; rows=json.loads((R/'news/download-results.json').read_text(encoding='utf-8'))
for x in rows:
    if ('准确日' in x['date_note'] or '具体日' in x['date_note'] or '精确' in x['date_note'] or x['id'] in ['N075','N084','N085','N083']):
        txt=(R/x['text_file']).read_text(encoding='utf-8') if x.get('text_file') else ''
        matches=re.findall(r'(?:20\d{2}[年/-]\s*\d{1,2}[月/-]\s*\d{1,2}日?|(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\s+\d{1,2},?\s+20\d{2})',txt,re.I)
        print(x['id'],x['title'],list(dict.fromkeys(matches))[:8])
        if x['id']=='N075':print('OWASP content:',txt[-1800:])
        if x['id'] in ['N084','N085']:print('Author:',txt[:800])
x=next(x for x in rows if x['id']=='N052')
url=urllib.parse.quote(x['url'],safe=':/?&=%#@+,;')
req=urllib.request.Request(url,headers={'Range':'bytes=524288-1048575','User-Agent':'Mozilla/5.0'})
with urllib.request.urlopen(req,timeout=35) as r:
    print('PDF_RANGE',r.status,{k:r.headers.get(k) for k in ('Content-Range','Content-Length','Content-Type')});data=r.read(1024*1024)
    (R/'news/pdf-range-probe.bin').write_bytes(data)
