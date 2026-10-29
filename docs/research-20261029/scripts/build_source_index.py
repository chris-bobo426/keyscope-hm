import base64,csv,hashlib,html,json,pathlib,re,urllib.parse,sys
sys.stdout.reconfigure(encoding='utf-8')
ROOT=pathlib.Path(__file__).resolve().parents[1]
attempts=[]
for p in sorted((ROOT/'sources').glob('download-plan*-results.json')):
    for x in json.loads(p.read_text(encoding='utf-8')):
        x['attempt_log']=p.name; attempts.append(x)
byfile={}
for x in attempts: byfile.setdefault(x['file'],[]).append(x)
known_bad={
 'downloads/news/OpenHarmony-security-2026-10.md':'html_shell_not_markdown',
 'downloads/docs/deveco-snapshot.html':'spa_shell_no_document_body',
 'downloads/news/CVE-2024-21826.html':'wrong_page_nvd_home',
}
index=[]
for n,(path,history) in enumerate(sorted(byfile.items()),1):
    last=history[-1]; p=ROOT/path
    row={'source_id':f'S{n:03d}','name':p.name,'file':path,'url':last['url'],'accessed_at':last.get('accessed_at'),'http_status':last.get('status'),'bytes':None,'sha256':None,'content_status':'download_failed','note':last.get('error',''),'attempt_logs':list(dict.fromkeys(h['attempt_log'] for h in history)),'version_or_pin':'','license_note':'publisher_or_repository_terms; not blanket redistribution permission'}
    if p.exists():
        body=p.read_bytes();row.update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),content_status='downloaded_format_checked')
        if path in known_bad: row.update(content_status=known_bad[path],note='HTTP200但正文不符合目标；替代来源已保存')
        elif p.suffix=='.pdf':
            row['content_status']='valid_pdf';row['note']='已用pypdf解析页数，详见collection-validation.json'
            if 'whitepaper' in path: row['note']+='；自动文字抽取含乱码，具体页需视觉核对'
        elif p.suffix=='.md' and body.lstrip().lower().startswith((b'<!doctype html',b'<html')):row['content_status']='unexpected_html'
        elif p.suffix=='.json':
            try:json.loads(body);row['content_status']='valid_json'
            except ValueError:row['content_status']='invalid_json'
        elif p.suffix=='.zip':row['content_status']='zip_crc_verified'
        elif p.suffix=='.tgz':row['content_status']='tgz_readable'
        successful=next((h for h in reversed(history) if h.get('downloaded') and h.get('sha256')==row['sha256']),None)
        if successful:
            row['url']=successful['url'];row['accessed_at']=successful['accessed_at'];row['http_status']=successful.get('status')
        else: row['note']+='；现存文件与下载日志hash不一致，须复查'
    pins=re.findall(r'/([a-f0-9]{40})(?:/|\?|$)',row['url'])
    if pins:row['version_or_pin']=pins[0]
    elif 'arkanalyzer-1.0.95' in path:row['version_or_pin']='1.0.95'
    elif 'JScamd-v3' in path:row['version_or_pin']='Zenodo 20567432 / v3'
    elif path.endswith('NIST-SP800-57pt1r6-DRAFT.pdf'):row['version_or_pin']='Revision6 initial public draft, not final'
    if '/official-samples/' in path:row['license_note']='see downloads/official-samples/LICENSE'
    elif 'JScamd' in path:row['license_note']='Zenodo record CC-BY-4.0; third-party components retain own terms'
    elif 'CryptoAPI-Bench' in path:row['license_note']='repository archive includes MIT LICENSE; paper retains publisher terms'
    elif any(k in path for k in ('CrossFlowBench','ArkTaint','ArkAnalyzer-Lab')):row['license_note']='no top-level project license verified in downloaded archive'
    index.append(row)
(ROOT/'sources/source-index.json').write_text(json.dumps(index,ensure_ascii=False,indent=2),encoding='utf-8')
cols=['source_id','name','file','url','accessed_at','http_status','bytes','sha256','content_status','version_or_pin','license_note','note']
with (ROOT/'sources/source-index.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore');w.writeheader();w.writerows(index)
lines=['# 原始资料索引','', '此索引按目标文件去重；失败重试的完整历史保留在 download-plan*-results.json。源编号为S序列，原下载批次中的id可能跨批复用，引用时以S编号/路径/URL为准。`format_checked`仅表明格式与内容入口已检查，不代表全文逐句验证。','', '[CSV](source-index.csv)含完整SHA-256，[JSON](source-index.json)含版本、许可备注与批次记录。','', '| ID | 文件 | 原始来源 | 内容状态 |','|---|---|---|---|']
for x in index:
    local=f"[{x['file']}](../{urllib.parse.quote(x['file'],safe='/')})" if (ROOT/x['file']).exists() else x['file']+'（未下载）'
    lines.append(f"| {x['source_id']} | {local} | [来源]({x['url']}) | {x['content_status']} |")
(ROOT/'sources/资料索引.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
# Extract bounded plain text from primary HTML for exact signature checks, never execute page code.
for name in ['openssl-pbkdf2','openssl-derive']:
    raw=(ROOT/f'downloads/docs/{name}.html').read_text(encoding='utf-8',errors='replace')
    raw=re.sub(r'<(?:script|style)\b[^>]*>.*?</(?:script|style)>','',raw,flags=re.S|re.I)
    plain=html.unescape(re.sub('<[^>]+>',' ',raw));plain=re.sub(r'[ \t]+',' ',plain)
    (ROOT/f'sources/{name}-text.txt').write_text(plain,encoding='utf-8')
    if name=='openssl-pbkdf2':
        compact=re.sub(r'\s+',' ',plain)
        match=re.search(r'int\s+PKCS5_PBKDF2_HMAC\s*\(',compact)
        print('PBKDF2 signature:',compact[match.start():match.start()+550] if match else 'NOT FOUND')
npm=json.loads((ROOT/'sources/arkanalyzer-npm.json').read_text(encoding='utf-8'))
dist=npm['versions']['1.0.95']['dist'];expected=dist.get('integrity')
blob=(ROOT/'downloads/repos/arkanalyzer-1.0.95.tgz').read_bytes()
actual='sha512-'+base64.b64encode(hashlib.sha512(blob).digest()).decode()
z=json.loads((ROOT/'sources/JScamd-zenodo-record.json').read_text(encoding='utf-8'))
zf=next(x for x in z['files'] if x['key']=='JScamd.zip')
jactual='md5:'+hashlib.md5((ROOT/'downloads/repos/JScamd-v3.zip').read_bytes()).hexdigest()
checks={'npm_arkanalyzer_1_0_95_integrity_match':expected==actual,'zenodo_jscamd_checksum_match':zf['checksum']==jactual,'source_records':len(index),'unique_downloaded_files':sum((ROOT/x['file']).exists() for x in index),'unusable_content':[x['file'] for x in index if x['content_status'] in known_bad.values()],'failed_missing':[x['file'] for x in index if not (ROOT/x['file']).exists()]}
(ROOT/'sources/upstream-integrity.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(checks,ensure_ascii=False,indent=2))
print('npm tags',npm['dist-tags'],'release',npm['time'].get('1.0.95'),npm['time'].get('2.0.0-beta1'))
for name in ['ReArk-latest-release','HapRay-repo','ArkTaint-repo']:
    x=json.loads((ROOT/f'sources/{name}.json').read_text(encoding='utf-8'));print(name,{k:x.get(k) for k in ['tag_name','published_at','pushed_at','html_url']})
