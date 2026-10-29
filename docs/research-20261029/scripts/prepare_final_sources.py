import json, pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
def item(i,u,f): return {'id':i,'url':u,'file':f}
plan=[
item('D24','https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf','downloads/papers/NIST-SP800-38D.pdf'),
item('D25','https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r6.ipd.pdf','downloads/papers/NIST-SP800-57pt1r6-DRAFT.pdf'),
item('N06','https://csrc.nist.gov/pubs/sp/800/57/pt1/r6/ipd','downloads/news/NIST-key-management-rev6-draft.html'),
item('N07','https://cveawg.mitre.org/api/cve/CVE-2024-21826','sources/CVE-2024-21826.json'),
item('N08','https://nvd.nist.gov/vuln/detail/CVE-2024-21826','downloads/news/CVE-2024-21826.html'),
item('C02','https://huaqin.xidian.edu.cn/archives/','downloads/competition/archives.html'),
item('D26','https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/','downloads/docs/openssl-pbkdf2.html'),
item('D27','https://raw.githubusercontent.com/openharmony/security/master/zh/security-disclosure/2024/2024-03.md','downloads/news/OpenHarmony-security-2024-03.md'),
]
tree=json.loads((ROOT/'sources/official-samples-tree.json').read_text(encoding='utf-8'))
paths={'crypto':'code/BasicFeature/Security/CryptoFramework','huks':'code/BasicFeature/Security/Huks','napi-arraybuffer':'code/DocsSample/ArkTS/NodeAPI/NodeAPIUse/NodeAPIArraybuffer'}
for name,path in paths.items():
    entry=next(x for x in tree['tree'] if x['path']==path)
    plan.append(item('TREE-'+name,'https://api.github.com/repos/openharmony/applications_app_samples/git/trees/'+entry['sha']+'?recursive=1','sources/sample-tree-'+name+'.json'))
(ROOT/'sources/download-plan6.json').write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
print('plan6',len(plan))
