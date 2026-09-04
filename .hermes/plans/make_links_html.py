from pathlib import Path
import json, html

md = Path(r'G:\Mon Drive\ZHermes Agent\Bachelor Thesis\presentations\Milestone1_Source_Links.md')
rows=[]
for line in md.read_text(encoding='utf-8').splitlines():
    if not line.startswith('| ') or line.startswith('|---') or line.startswith('| Finding'):
        continue
    cells=[x.strip() for x in line.strip('|').split('|')]
    if len(cells)<6: continue
    finding,slide,title,page,link,note=cells[:6]
    url=link.split('](')[-1].rstrip(')') if '](' in link else link
    rows.append((finding,slide,title,page,url,note))

def esc(x): return html.escape(x, quote=True)
body=[]
for f,s,t,p,u,n in rows:
    body.append(f'<tr><td>{esc(f)}</td><td>{esc(s)}</td><td>{esc(t)}</td><td>p. {esc(p)}</td><td><a href="{esc(u)}" target="_blank">Open source ↗</a><div class="url">{esc(u)}</div></td><td>{esc(n)}</td></tr>')
page=f'''<!doctype html><html><head><meta charset="utf-8"><title>Milestone 1 — Direct Source Links</title><style>
body{{font-family:Arial,sans-serif;margin:32px;color:#172033;background:#f7f9fc}}h1{{font-size:26px;margin-bottom:6px}}p{{color:#637083}}table{{width:100%;border-collapse:collapse;background:white;border:1px solid #dbe3ec;border-radius:8px;overflow:hidden}}th{{text-align:left;background:#102238;color:white;font-size:12px;padding:10px}}td{{vertical-align:top;border-top:1px solid #e6ebf1;padding:10px;font-size:12px;line-height:1.35}}a{{color:#0d6e8a;font-weight:700;text-decoration:none}}a:hover{{text-decoration:underline}}.url{{font-size:10px;color:#718096;margin-top:4px;word-break:break-all}}tr:nth-child(even){{background:#fbfcfe}}</style></head><body><h1>Milestone 1 PowerPoint — Direct Source Links</h1><p>37-row map for manual screenshots. Every link points to the original paper, report, or official source page. The page number is the excerpt targeted in the deck.</p><table><thead><tr><th>Finding</th><th>Slide</th><th>Finding title</th><th>Page</th><th>Direct source</th><th>Screenshot note</th></tr></thead><tbody>{''.join(body)}</tbody></table></body></html>'''
out=Path(r'G:\Mon Drive\ZHermes Agent\Bachelor Thesis\presentations\Milestone1_Source_Links.html')
out.write_text(page,encoding='utf-8')
print(out,len(rows),out.stat().st_size)
