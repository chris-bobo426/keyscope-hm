"""Read-only public-source collector. Never runs downloaded code."""
import concurrent.futures, datetime, hashlib, json, pathlib, sys, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]

def fetch(item):
    row = dict(item)
    row['accessed_at'] = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
    try:
        url = urllib.parse.quote(item['url'], safe=':/?&=%#@+,;')
        req = urllib.request.Request(url, headers={'User-Agent': 'KeyScope-research-collector/1.0', 'Accept': '*/*'})
        with urllib.request.urlopen(req, timeout=35) as response:
            body = response.read(100 * 1024 * 1024 + 1)
            if len(body) > 100 * 1024 * 1024:
                raise ValueError('Source exceeds 100 MiB per-file bound')
            row.update(status=response.status, final_url=response.url, content_type=response.headers.get('Content-Type'))
        dest = (ROOT / item['file']).resolve()
        if not dest.is_relative_to(ROOT):
            raise ValueError('Output must stay in research directory')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body)
        row.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), downloaded=True)
    except Exception as exc:
        row.update(downloaded=False, error=str(exc))
    return row

if __name__ == '__main__':
    plan = pathlib.Path(sys.argv[1])
    items = json.loads(plan.read_text(encoding='utf-8-sig'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        result = list(pool.map(fetch, items))
    out = ROOT / 'sources' / (plan.stem + '-results.json')
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    for row in result:
        print(json.dumps({k: row[k] for k in ('id','downloaded','bytes','error') if k in row}, ensure_ascii=False))
