import json
with open('wordfence_production_db.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
for vuln_id, info in data.items():
    for sw in info.get('software', []):
        if sw.get('slug') == 'wp-fastest-cache' and sw.get('patched'):
            print(f'ID: {vuln_id}')
            print(f'Title: {info.get("title", "")}')
            print(f'CVE: {info.get("cve", "")}')
            print(f'Patched versions: {sw.get("patched_versions", [])}')
            print(f'Affected versions: {sw.get("affected_versions", {})}')
            print('---')
