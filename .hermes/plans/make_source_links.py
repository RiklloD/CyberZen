import json, os, urllib.request, urllib.error
from pathlib import Path

manifest_path = Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots\manifest.json')
manifest = json.loads(manifest_path.read_text(encoding='utf-8'))

URLS = {
    'eic_workprogramme_2026.pdf': 'https://eic.ec.europa.eu/system/files/2025-11/EIC-Work-Programme-2026.pdf',
    'raff_springer.pdf': 'https://link.springer.com/article/10.1007/s10961-026-10327-w',
    '37_Chen_2024_tto_playmakers.pdf': 'https://doi.org/10.1007/s10961-024-10123-4',
    '38_Hayter_2025_lean.pdf': 'https://doi.org/10.1007/s10961-025-10288-6',
    '04_Seitz_2026.pdf': 'https://doi.org/10.1007/s11846-026-01017-w',
    'capatina_foresight.pdf': 'https://www.elsevier.es/en-revista-journal-innovation-knowledge-376-pdf-download-S2444569X24000544',
    '39_Cantner_2024_aso.pdf': 'https://link.springer.com/article/10.1007/s11187-023-00815-w',
    '36_Denoo_2024_advisors.pdf': 'https://doi.org/10.1007/s10961-024-10125-2',
    'stryber.pdf': 'https://resources.stryber.com/blog/deep-tech-commercialization-in-europe',
    '19_UNDP_2025.pdf': 'https://www.undp.org/sites/g/files/zskgke326/files/2025-06/undp-global-deep-tech-ecosystems.pdf',
    '17_Kortsch_2024.pdf': 'https://mitsloan.mit.edu/shared/ods/documents?PublicationDocumentID=10845',
    'eic_accelerator.pdf': 'https://eic.ec.europa.eu/eic-funding-opportunities/eic-accelerator_en',
    'imperial_dtprime_v2.pdf': 'https://www.imperial.ac.uk/research-and-innovation/deep-tech-entrepreneurship/dt-prime',
    'blank_wicked_v3.pdf': 'https://steveblank.com/2023/07/25/lean-meets-wicked-problems/',
    'niti_tcrm_v2.pdf': 'https://www.niti.gov.in/node/873',
    'deeptechleaders_crl.pdf': 'https://www.deeptechleaders.com/deep-tech-startup-insights/communicating-progress-in-deep-tech-part-1',
    'innosuisse_coaching.pdf': 'https://www.innosuisse.admin.ch/en/start-up-coaching-for-start-up',
    'kof_innosuisse.pdf': 'https://www.innosuisse.admin.ch/dam/it/sd-web/veYrGjAgZwmP/2024_KOF%20Study_Funding%20R%26D%20Cooperation_Presentation%20of%20results.pdf',
    'switzerland_horizon_europe.pdf': 'https://research-and-innovation.ec.europa.eu/strategy/strategy-research-and-innovation/europe-world/international-cooperation/association-horizon-europe/switzerland_en',
    'cern_kt2025.pdf': 'https://ventureconnect.cern',
    'innosuisse_impact.pdf': 'https://innosuisse-impact.github.io/impact/en/',
    'swiss_deeptech_2025.pdf': 'https://www.deeptechnation.ch/resources/swiss-deep-tech-report-2025',
}
# These are the primary sources recommended for manual screenshots, even when a
# generated excerpt used a related static reproduction because the original page
# was JS-heavy.
NOTES = {
    ('FA', 'Candidates · CERN Venture Connect'): 'Use the official CVC page; the generated excerpt used a static Stryber page because the CVC site is interactive.',
    ('DC', 'Data · Switzerland #1 (100 vs 33)'): 'Use the original Deep Tech Nation report page; the generated excerpt used a static Swiss Startup Association reproduction.',
    ('LIT', 'Theme 1 · Deep tech is ecosystem-dependent'): 'The source article is published under Micol, Leendertse & van Rijnsoever (2026); the earlier Word synthesis called it Raff-Heinen.',
}

def basename(path): return os.path.basename(path)

def source_label(item):
    return basename(item['file'])

rows=[]
for i,item in enumerate(manifest,1):
    key=tuple(item['key']); url=URLS.get(source_label(item))
    if key == ('FA', 'Candidates · CERN Venture Connect'):
        url = 'https://ventureconnect.cern'
    if not url: raise SystemExit(f'Missing URL for {source_label(item)}')
    rows.append((i,key,item,url))

# Verify unique URLs resolve or at least return a redirect/HTTP response.
verify=[]
for url in dict.fromkeys(x[3] for x in rows):
    req=urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            verify.append((url, r.status, r.geturl()))
    except urllib.error.HTTPError as e:
        verify.append((url, e.code, e.geturl()))
    except Exception as e:
        verify.append((url, 'ERROR', type(e).__name__+': '+str(e)[:80]))

out=Path(r'G:\Mon Drive\ZHermes Agent\Bachelor Thesis\presentations\Milestone1_Source_Links.md')
lines=[]
lines.append('# Milestone 1 PowerPoint — Direct Source Links\n')
lines.append('Use these URLs to open the **actual cited paper, report, or official source** and take your own screenshot. Page numbers refer to the PDF/page excerpt targeted in the deck.\n')
lines.append('> The deck contains 37 findings: literature slides 3–13, framework slides 15–28, and data slides 30–41.\n')
lines.append('| Finding | Deck slide | Finding title | Source page | Direct source | Screenshot target / note |')
lines.append('|---:|---:|---|---:|---|---|')
for i,(n,key,item,url) in enumerate(rows,1):
    # Map finding order to actual deck slide number.
    slide = 2 + i if i <= 11 else (3 + 11 + i if i <= 25 else 4 + 25 + i)
    # Correct formula: 3-13, 15-28, 30-41.
    if i <= 11: slide = i + 2
    elif i <= 25: slide = i + 3
    else: slide = i + 4
    note=NOTES.get(key,'')
    target=f'p. {item["page"]}'
    if note: target += ' — ' + note
    lines.append(f'| {i} | {slide} | {key[1]} | {item["page"]} | [{url}]({url}) | {target} |')
lines.append('\n## Verified URL resolution\n')
for url,status,final in verify:
    lines.append(f'- `{status}` — {url}' + (f' → `{final}`' if final != url else ''))
out.write_text('\n'.join(lines)+'\n',encoding='utf-8')

# Compact JSON for programmatic reuse.
json_out=out.with_suffix('.json')
json_out.write_text(json.dumps([{'finding':i,'slide':(i+2 if i<=11 else i+3 if i<=25 else i+4),'key':list(key),'page':item['page'],'url':url,'note':NOTES.get(key,'')} for i,(n,key,item,url) in enumerate(rows,1)],ensure_ascii=False,indent=2),encoding='utf-8')
print('wrote',out,'rows',len(rows),'unique URLs',len(verify))
for u,s,f in verify: print(s,u)
