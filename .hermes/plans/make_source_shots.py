#!/usr/bin/env python3
"""Render clean source excerpts from primary papers/reports/pages.
No highlight layers, annotations, or synthetic text are added to the images.
Each image is a crop rendered directly from the cited source PDF.
"""
import os, re, json
import pypdfium2 as pdfium
from PIL import Image

OUT = r"C:\Dev\CyberZen\.hermes\plans\source_shots"
TMP = r"C:\Users\lorik\AppData\Local\Temp\realsrc"
PAPERS = r"G:\Mon Drive\ZHermes Agent\Bachelor Thesis\literature\papers"
os.makedirs(OUT, exist_ok=True)

# key = (original doc tag, original label). Queries are short, direct excerpts from the source.
M = [
# ---- Literature ----
{"key":["LIT","Theme 0 · The headline finding"],"file":os.path.join(TMP,"eic_workprogramme_2026.pdf"),"hint":26,"query":"earliest stages of scientific, technological or deep tech research and development","ref":"European Commission (2026), EIC Work Programme 2026, p. 26 (EIC Pathfinder)."},
{"key":["LIT","Theme 1 · Deep tech is ecosystem-dependent"],"file":os.path.join(TMP,"raff_springer.pdf"),"hint":1,"query":"knowledge and talent is more important","ref":"Micol, F., Leendertse, J. & van Rijnsoever, F. (2026), Journal of Technology Transfer 51, pp. 2886–2915."},
{"key":["LIT","Theme 2 · TTOs: relationships, not transactions"],"file":os.path.join(PAPERS,"37_Chen_2024_tto_playmakers.pdf"),"hint":16,"query":"TTOs are rapidly becoming playmakers","ref":"Chen, Z., Little, V. & Thuan, N. (2025), Journal of Technology Transfer 50, pp. 1060–1079."},
{"key":["LIT","Theme 3 · Structured frameworks outperform ad hoc"],"file":os.path.join(PAPERS,"38_Hayter_2025_lean.pdf"),"hint":1,"query":"modeled on the U.S. National Science Foundation’s Innovation Corps","ref":"Hayter, C. S. et al. (2025), Journal of Technology Transfer, DOI 10.1007/s10961-025-10288-6."},
{"key":["LIT","Theme 4 · Support must be configured, not provided"],"file":os.path.join(PAPERS,"04_Seitz_2026.pdf"),"hint":32,"query":"University incubator","ref":"Seitz, N. et al. (2026), Review of Managerial Science, DOI 10.1007/s11846-026-01017-w, Table of moderator effects."},
{"key":["LIT","Theme 5 · Market identification is the binding constraint"],"file":os.path.join(TMP,"capatina_foresight.pdf"),"hint":10,"query":"strongest impact enhanced foresight","ref":"Capatina, A., Bleoju, G. & Kalisz, D. (2024), Journal of Innovation & Knowledge 9, 100515."},
{"key":["LIT","Theme 5b · Cantner: commercial from day one"],"file":os.path.join(PAPERS,"39_Cantner_2024_aso.pdf"),"hint":2,"query":"greater importance than the academic sphere","ref":"Cantner, U. et al. (2024), Small Business Economics 62, pp. 1555–1590."},
{"key":["LIT","Theme 5c · Denoo: business advisors help, tech advisors delay"],"file":os.path.join(PAPERS,"36_Denoo_2024_advisors.pdf"),"hint":19,"query":"AR goes down by about 0.31","ref":"Denoo, L., Van Boxstael, A. & Belz, A. (2024), Journal of Technology Transfer 49, pp. 1567–1605."},
{"key":["LIT","Theme 6 · Europe's structural barriers"],"file":os.path.join(TMP,"stryber.pdf"),"hint":3,"query":"European Deep Tech firms secured just","ref":"Stryber (2025), Deep Tech commercialization in Europe: the gap, the challenge, and the fix."},
{"key":["LIT","Theme 6b · UNDP: 35% more time, 48% more capital"],"file":os.path.join(PAPERS,"19_UNDP_2025.pdf"),"hint":54,"query":"35% more time and 48% more capital","ref":"UNDP (2025), Global Deep Tech Ecosystems: Catalyzing Innovation for Sustainable Development, p. 54."},
{"key":["LIT","Theme 7 · Convergence on a deep tech definition"],"file":os.path.join(PAPERS,"17_Kortsch_2024.pdf"),"hint":1,"query":"twelve defining attributes structured across three levels","ref":"Kortsch, J. et al. (2024), Deep-Tech Innovation: A Multi-Method Study, MIT Sloan / University of Münster."},
# ---- Frameworks ----
{"key":["FA","Framework gap · The central finding"],"file":os.path.join(TMP,"eic_accelerator.pdf"),"hint":1,"query":"TRL 6-8","ref":"European Innovation Council (2026), EIC Accelerator official programme page."},
{"key":["FA","RCA/Imperial · What the module actually is"],"file":os.path.join(TMP,"imperial_dtprime_v2.pdf"),"hint":1,"query":"Turning breakthrough research into investable ventures","ref":"Imperial College London, DT Prime, Institute for Deep Tech Entrepreneurship (official page)."},
{"key":["FA","RCA/Imperial · Flipped Lean Startup"],"file":os.path.join(TMP,"blank_wicked_v3.pdf"),"hint":8,"query":"combine the tenets of Lean","ref":"Blank, S. (2023), Lean Meets Wicked Problems, Steve Blank blog / Imperial College Business School class account."},
{"key":["FA","CRL · The 9-point scale"],"file":os.path.join(TMP,"niti_tcrm_v2.pdf"),"hint":31,"query":"CRL 1 Basic value proposition of technology identified and reported","ref":"NITI Aayog (2023), A New Lens for Innovation in New India: TCRM Matrix, p. 31."},
{"key":["FA","CRL · The documentation problem"],"file":os.path.join(TMP,"deeptechleaders_crl.pdf"),"hint":8,"query":"Commercial Readiness Level framework","ref":"Deep Tech Leaders (2025), TRL, MRL & CRL Explained, Part 1, p. 8."},
{"key":["FA","CRL · No published methodology"],"file":os.path.join(TMP,"niti_tcrm_v2.pdf"),"hint":32,"query":"TRLs only take into account a technology’s technical readiness","ref":"NITI Aayog (2023), TCRM Matrix, p. 32 (identifying the limits of TRL and the need for commercial readiness)."},
{"key":["FA","Innosuisse · The native framework"],"file":os.path.join(TMP,"innosuisse_coaching.pdf"),"hint":1,"query":"The Start-up Coaching is aimed at young companies and their founders","ref":"Innosuisse (official), Start-up Coaching overview."},
{"key":["FA","Innosuisse · Custom, not codified"],"file":os.path.join(TMP,"innosuisse_coaching.pdf"),"hint":2,"query":"Initial Coaching grants you a voucher worth up to CHF 10 000","ref":"Innosuisse (official), Start-up Coaching overview, voucher-based programme description."},
{"key":["FA","Innosuisse · KOF causal evidence"],"file":os.path.join(TMP,"kof_innosuisse.pdf"),"hint":21,"query":"average effect of 20.7% after five years","ref":"Hulfeld, F., Spescha, A. & Wörter, M. (KOF ETH Zurich, 2024), Funding R&D Cooperation between Firms and Universities."},
{"key":["FA","Innosuisse · The TRL 1–3 structural gap"],"file":os.path.join(TMP,"innosuisse_coaching.pdf"),"hint":2,"query":"Scale-up Coaching grants you a voucher","ref":"Innosuisse (official), Start-up Coaching overview — stage-specific support and durations."},
{"key":["FA","EIC · The accelerator gap"],"file":os.path.join(TMP,"eic_accelerator.pdf"),"hint":1,"query":"TRL 6-8","ref":"European Innovation Council (official), EIC Accelerator programme page."},
{"key":["FA","EIC · Swiss eligibility restored Jan 2025"],"file":os.path.join(TMP,"switzerland_horizon_europe.pdf"),"hint":2,"query":"on similar terms with EU Member States","ref":"European Commission (official), International cooperation with Switzerland in research and innovation."},
{"key":["FA","Candidates · CERN Venture Connect"],"file":os.path.join(TMP,"stryber.pdf"),"hint":3,"query":"CERN Venture Connect Programme Lead at CERN","ref":"Stryber (2025), Deep Tech commercialization in Europe — source identifying CERN Venture Connect as a relevant institutional actor."},
{"key":["FA","Candidates · I-Corps"],"file":os.path.join(PAPERS,"38_Hayter_2025_lean.pdf"),"hint":4,"query":"structured customer discovery and business model development","ref":"Hayter, C. S. et al. (2025), Journal of Technology Transfer, p. 4."},
# ---- Data ----
{"key":["DC","Data · The binding constraint"],"file":os.path.join(TMP,"capatina_foresight.pdf"),"hint":10,"query":"path coefficient = 0.514","ref":"Capatina, A., Bleoju, G. & Kalisz, D. (2024), Journal of Innovation & Knowledge 9, 100515, structural model."},
{"key":["DC","Data · Ecosystem: talent IRR=1.66"],"file":os.path.join(TMP,"raff_springer.pdf"),"hint":40,"query":"Specificknowledge","ref":"Micol, F., Leendertse, J. & van Rijnsoever, F. (2026), Journal of Technology Transfer, Table 4."},
{"key":["DC","Data · Incubation: university r=0.118"],"file":os.path.join(PAPERS,"04_Seitz_2026.pdf"),"hint":32,"query":"University incubator 10 1520 0.118","ref":"Seitz, N. et al. (2026), Review of Managerial Science, moderator table."},
{"key":["DC","Data · Advisors: +0.23 vs −0.31"],"file":os.path.join(PAPERS,"36_Denoo_2024_advisors.pdf"),"hint":19,"query":"roughly 4 business advisors can advance AR by a full unit","ref":"Denoo, L., Van Boxstael, A. & Belz, A. (2024), Journal of Technology Transfer, p. 1585."},
{"key":["DC","Data · TTO survival: p=0.0034"],"file":os.path.join(PAPERS,"37_Chen_2024_tto_playmakers.pdf"),"hint":16,"query":"building relationships within the wider university innovation service ecosystem","ref":"Chen, Z., Little, V. & Thuan, N. (2025), Journal of Technology Transfer, p. 1075."},
{"key":["DC","Data · Switzerland #1 (100 vs 33)"],"file":os.path.join(TMP,"swiss_deeptech_2025.pdf"),"hint":3,"query":"60 percent of all domestic venture funding","ref":"Deep Tech Nation Switzerland / Dealroom.co (2025), Swiss Deep Tech Report 2025, via Swiss Startup Association reproduction."},
{"key":["DC","Data · Innosuisse: 57% market launch"],"file":os.path.join(TMP,"innosuisse_impact.pdf"),"hint":2,"query":"Market launch: Three years after the funding has ended","ref":"Innosuisse (2025), Impact monitoring 2021–2023."},
{"key":["DC","Data · BRIDGE: 70% founding rate"],"file":os.path.join(TMP,"innosuisse_impact.pdf"),"hint":3,"query":"Around 70% of the supported researchers found astart-up","ref":"Innosuisse (2025), Impact monitoring 2021–2023, BRIDGE Proof of Concept."},
{"key":["DC","Data · KOF DiD: +20.7% sales"],"file":os.path.join(TMP,"kof_innosuisse.pdf"),"hint":21,"query":"sales that increase over time, with an average effect of 20.7%","ref":"Hulfeld, F., Spescha, A. & Wörter, M. (KOF ETH Zurich, 2024), causal difference-in-differences result."},
{"key":["DC","Data · TRL coverage gap"],"file":os.path.join(TMP,"niti_tcrm_v2.pdf"),"hint":30,"query":"TRL 1 Basic principles observed and reported","ref":"NITI Aayog (2023), TCRM Matrix, p. 30 (TRL scale)."},
{"key":["DC","Data · EU vs US: €58B vs €215B"],"file":os.path.join(TMP,"stryber.pdf"),"hint":3,"query":"European Deep Tech firms secured just","ref":"Stryber (2025), Deep Tech commercialization in Europe."},
{"key":["DC","Data · Deep tech: +35% time, +48% capital"],"file":os.path.join(PAPERS,"19_UNDP_2025.pdf"),"hint":54,"query":"deep tech startups often require 35% more time and 48% more capital","ref":"UNDP (2025), Global Deep Tech Ecosystems, p. 54."},
]

# Character normalization for PDF text quirks.
def clean(s):
    s = s.replace('\ufffe','').replace('\ufffd','').replace('\u00ad','')
    s = s.replace('\u2018',"'").replace('\u2019',"'")
    s = s.replace('\u201c','"').replace('\u201d','"')
    return re.sub(r'\s+',' ',s).strip()

def stream(tp):
    out=[]; idx=[]; n=tp.count_chars()
    for i in range(n):
        try: c=tp.get_text_range(i,1)
        except: c=''
        if c in ('\r','\n','\t','\x00','\ufffe','\ufffd','\u00ad'): continue
        out.append(c); idx.append(i)
    return clean(''.join(out)), idx

def locate(page, query):
    tp=page.get_textpage(); s, idx=stream(tp); q=clean(query)
    pos=s.lower().find(q.lower())
    if pos < 0: return None
    u=None
    for k in range(pos,pos+len(q)):
        try: box=tp.get_charbox(idx[k])
        except: box=None
        if box:
            l,t,r,b=box
            if u is None: u=[l,t,r,b]
            else: u=[min(u[0],l),min(u[1],t),max(u[2],r),max(u[3],b)]
    return u

def find(item):
    d=pdfium.PdfDocument(item['file'])
    order=[item.get('hint',1)-1]+[i for i in range(len(d)) if i != item.get('hint',1)-1]
    for i in order:
        if i<0 or i>=len(d): continue
        b=locate(d[i],item['query'])
        if b:
            d.close(); return i,b
    d.close(); return None,None

def render(item, page_no, bbox, scale=2.0, min_w=390, min_h=145):
    d=pdfium.PdfDocument(item['file']); page=d[page_no]; pw,ph=page.get_size()
    l,t,r,b=bbox; cw,ch=r-l,b-t
    # Keep enough original surrounding context for clean, readable source screenshots.
    if cw < min_w:
        add=(min_w-cw)/2; l=max(0,l-add); r=min(pw,r+add)
    if ch < min_h:
        add=(min_h-ch)/2; t=max(0,t-add); b=min(ph,b+add)
    # Include more context above for text/table snippets, without adding any annotation.
    top=max(0,t-22); bottom=min(ph,b+22); left=max(0,l-22); right=min(pw,r+22)
    bmp=page.render(scale=scale); im=bmp.to_pil().convert('RGB')
    crop=im.crop((int(left*scale),int(top*scale),int(right*scale),int(bottom*scale)))
    d.close(); return crop

def main():
    results=[]; misses=[]
    for n,item in enumerate(M,1):
        p,b=find(item)
        if b is None:
            misses.append(item); print('MISS',item['key'],item['query']); continue
        im=render(item,p,b)
        fname=f"source_{n:02d}.png"; im.save(os.path.join(OUT,fname), optimize=True)
        results.append({**item,'file_out':fname,'page':p+1,'size':im.size})
        print('OK',n,item['key'][1], 'p',p+1, im.size)
    with open(os.path.join(OUT,'manifest.json'),'w',encoding='utf-8') as f: json.dump(results,f,ensure_ascii=False,indent=2)
    print('RESULT',len(results),'/',len(M),'misses',len(misses))
    if misses:
        print('MISSING KEYS:',[x['key'] for x in misses])
        raise SystemExit(2)
if __name__=='__main__': main()
