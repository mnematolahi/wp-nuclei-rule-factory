import os, json
from wp_rule_factory.yaml_parser import parse_single_yaml

with open('wordfence_production_db.json', 'r', encoding='utf-8') as f:
    wf = json.load(f)

wf_slugs = set()
for vuln_id, info in wf.items():
    for sw in info.get('software', []):
        if sw.get('patched'):
            wf_slugs.add(sw.get('slug'))

# Focus on recent years and common plugins
target_dirs = ['nuclei-templates/2020', 'nuclei-templates/2021', 'nuclei-templates/2022', 
               'nuclei-templates/2023', 'nuclei-templates/2024', 'nuclei-templates/2025',
               'nuclei-templates/2026']

matches = []
checked = 0
for target_dir in target_dirs:
    if not os.path.isdir(target_dir):
        continue
    for fn in os.listdir(target_dir):
        if not fn.endswith('.yaml'):
            continue
        path = os.path.join(target_dir, fn)
        result = parse_single_yaml(path)
        checked += 1
        if not result:
            continue
        slug = result['slug']
        if slug in wf_slugs:
            matches.append((path, slug, result['vulnerable_version'], result['rule_id']))

print(f'Checked {checked} templates, found {len(matches)} WF matches in recent years')
for m in matches[:30]:
    print(m)
