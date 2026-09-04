#!/usr/bin/env python3
"""Accurate source screenshot renderer v2.
Handles rotated PDF content and converts pypdfium2 bottom-left boxes to PIL top-left crops.
"""
import json, os, re
from pathlib import Path
from PIL import Image
import pypdfium2 as pdfium

OLD_MANIFEST=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots\manifest.json')
OUT=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v2')
SRC=Path(r'C:\Users\lorik\AppData\Local\Temp\realsrc_v2')
OUT.mkdir(parents=True,exist_ok=True)
items=json.loads(OLD_MANIFEST.read_text(encoding='utf-8'))

# page/file-specific rendering choices learned from visual inspection.
ROTATED_FULL={('04_Seitz_2026.pdf',32):90}
FULL_TABLE={('raff_springer.pdf',40),( 'niti_tcrm_v2.pdf',30),( 'niti_tcrm_v2.pdf',31)}

def clean(s):
    s=s.replace('\ufffe','').replace('\ufffd','').replace('\u00ad','')
    s=s.replace('\u2018',"'").replace('\u2019',"'").replace('\u201c','"').replace('\u201d','"')
    return re.sub(r'\s+',' ',s).strip()

def compact_stream(tp):
    chars=[]; idx=[]
    for i in range(tp.count_chars()):
        try:c=tp.get_text_range(i,1)
        except:c=''
        if c in ('\r','\n','\t','\x00','\ufffe','\ufffd','\u00ad'): continue
        chars.append(c); idx.append(i)
    return clean(''.join(chars)),idx

def locate(page,query):
    tp=page.get_textpage(); s,idx=compact_stream(tp)
    q=clean(query)
    # First compact whitespace, then try a normal search as fallback.
    compact_s=re.sub(r'\s+','',s).lower(); compact_q=re.sub(r'\s+','',q).lower()
    pos=compact_s.find(compact_q)
    if pos<0:
        pos=s.lower().find(q.lower())
        if pos<0:return None
        # map normal position back by walking original stream
        compact_s2=[]; map2=[]
        for j,c in enumerate(s):
            if not c.isspace(): compact_s2.append(c); map2.append(j)
        pos2=''.join(compact_s2).lower().find(compact_q)
        if pos2<0:return None
        pos=pos2
    # Build char boxes over compact stream; the clean function can remove a few chars,
    # but source queries use standard text so the direct map is stable here.
    u=None
    for k in range(pos,pos+len(compact_q)):
        if k>=len(idx):break
        try:box=tp.get_charbox(idx[k])
        except:box=None
        if box:
            l,y1,r,y2=box
            if u is None:u=[l,y1,r,y2]
            else:u=[min(u[0],l),min(u[1],y1),max(u[2],r),max(u[3],y2)]
    return u

def render_item(item,n):
    basename=os.path.basename(item['file'])
    path=SRC/basename
    if not path.exists(): raise FileNotFoundError(path)
    d=pdfium.PdfDocument(str(path)); page_no=item['page']-1; page=d[page_no]; pw,ph=page.get_size()
    rot=ROTATED_FULL.get((basename,item['page']),0)
    scale=4.0
    if (basename,item['page']) in ROTATED_FULL:
        im=page.render(scale=3.0,rotation=rot).to_pil().convert('RGB')
        # Whole original table page, now correctly oriented.
        d.close(); return im
    if (basename,item['page']) in FULL_TABLE:
        im=page.render(scale=3.0).to_pil().convert('RGB')
        d.close(); return im
    bbox=locate(page,item['query'])
    if not bbox:
        d.close(); raise RuntimeError(f"quote not found: {basename} p{item['page']} {item['query']}")
    # pypdfium2 char boxes: x left/right, y values in bottom-left PDF coordinates.
    x1,y1,x2,y2=bbox
    pdf_bottom=min(y1,y2); pdf_top=max(y1,y2)
    # Convert to top-left image coordinates before padding.
    top_img=ph-pdf_top; bottom_img=ph-pdf_bottom
    # Keep complete source lines and enough surrounding context.
    if x1>pw*.42: # likely right column
        left=max(0,x1-22); right=min(pw,x2+145)
    else:
        left=max(0,x1-35); right=min(pw,x2+45)
    top=max(0,top_img-75); bottom=min(ph,bottom_img+180)
    bmp=page.render(scale=scale); im=bmp.to_pil().convert('RGB')
    crop=im.crop((int(left*scale),int(top*scale),int(right*scale),int(bottom*scale)))
    d.close(); return crop

results=[]
for n,item in enumerate(items,1):
    outname=f'source_{n:02d}.png'
    try:
        im=render_item(item,n); im.save(OUT/outname,optimize=True)
        results.append({**item,'file_out':outname,'size':im.size,'source_file':os.path.basename(item['file'])})
        print('OK',n,item['key'][1],im.size)
    except Exception as e:
        print('FAIL',n,item['key'][1],repr(e)); raise
(OUT/'manifest.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print('DONE',len(results))
