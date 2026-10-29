import json, pathlib, hashlib, zipfile, tarfile
from pypdf import PdfReader
ROOT=pathlib.Path(__file__).resolve().parents[1]
report={'pdfs':[], 'archives':[], 'official_samples':[]}
for p in sorted((ROOT/'downloads/papers').glob('*.pdf')):
    r=PdfReader(p)
    out=ROOT/'sources/paper-text'/(p.stem+'.txt')
    if not out.exists():
        out.write_text('\n\n'.join(f'=== PAGE {i+1} ===\n'+(page.extract_text() or '') for i,page in enumerate(r.pages)),encoding='utf-8')
    report['pdfs'].append({'file':str(p.relative_to(ROOT)).replace('\\','/'),'pages':len(r.pages),'valid_pdf':p.read_bytes()[:5]==b'%PDF-'})
for p in sorted((ROOT/'downloads/repos').iterdir()):
    if p.suffix=='.zip':
        with zipfile.ZipFile(p) as z:
            bad=z.testzip()
            names=z.namelist()
            licenses=[n for n in names if pathlib.PurePosixPath(n).name.lower() in ('license','license.md','license.txt','copying') and '/.git/' not in n]
            report['archives'].append({'file':str(p.relative_to(ROOT)).replace('\\','/'),'entries':len(names),'crc_error':bad,'license_paths':licenses})
            # Only unpack small source archives, never execute anything from them.
            if p.name.startswith(('CryptoAPI-Bench-','ArkAnalyzer-Lab-')):
                dest=ROOT/'downloads/extracted'/p.stem
                for info in z.infolist():
                    target=(dest/info.filename).resolve()
                    if not target.is_relative_to(dest.resolve()) or (info.external_attr >> 16)&0o170000==0o120000:
                        raise ValueError('unsafe archive entry')
                z.extractall(dest)
    elif p.suffix=='.tgz':
        with tarfile.open(p) as t:
            members=t.getmembers()
            report['archives'].append({'file':str(p.relative_to(ROOT)).replace('\\','/'),'entries':len(members),'readable':True,'license_paths':[m.name for m in members if pathlib.PurePosixPath(m.name).name.lower().startswith('license')]})
paths={'crypto':'code/BasicFeature/Security/CryptoFramework','huks':'code/BasicFeature/Security/Huks','napi-arraybuffer':'code/DocsSample/ArkTS/NodeAPI/NodeAPIUse/NodeAPIArraybuffer'}
for name,prefix in paths.items():
    data=json.loads((ROOT/f'sources/sample-tree-{name}.json').read_text(encoding='utf-8'))
    checks=[]
    for e in data['tree']:
        if e['type']!='blob': continue
        p=ROOT/'downloads/official-samples'/name/e['path']
        body=p.read_bytes() if p.exists() else b''
        actual=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
        checks.append({'file':e['path'],'exists':p.exists(),'git_blob_sha_matches':actual==e['sha']})
    report['official_samples'].append({'name':name,'subtree_sha':data['sha'],'truncated':data.get('truncated'),'files':len(checks),'missing':[x['file'] for x in checks if not x['exists']],'hash_mismatch':[x['file'] for x in checks if not x['git_blob_sha_matches']]})
(ROOT/'sources/collection-validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
