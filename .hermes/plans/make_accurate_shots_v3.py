#!/usr/bin/env python3
"""Targeted v3 screenshot fixes after visual review of the v2 contact sheets."""
import json, os, shutil, re
from pathlib import Path
import pypdfium2 as pdfium
from PIL import Image

OLD=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v2\manifest.json')
OUT=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v3')
SRC=Path(r'C:\Users\lorik\AppData\Local\Temp\realsrc_v2')
BASE=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v2')
OUT.mkdir(parents=True,exist_ok=True)
items=json.loads(OLD.read_text(encoding='utf-8'))

# Local direct article PDF fixes for the Springer HTML/cookie version.
LOCAL_FILE_OVERRIDES={
  2:'raff_direct.pdf',
  27:'raff_direct.pdf',
}
PAGE_OVERRIDES={27:26}
# Manual geometry fixes. Regions are fractions of the unrotated rendered page (top-left image coordinates).
REGIONS={
  1:(0.0,0.00,1.0,0.55),        # EIC Pathfinder: include the complete section heading
  2:(0.0,0.00,1.0,0.56),        # direct Springer PDF: title + abstract, not the full article page
  3:(0.0,0.00,1.0,0.68),        # Chen: full-width source text, avoid narrow-column crop
  7:(0.0,0.00,1.0,0.58),        # Cantner: abstract + commercial-sphere conclusion
  11:(0.0,0.00,1.0,0.48),       # Kortsch: abstract with all twelve attributes
  13:(0.0,0.27,1.0,0.75),       # Imperial DT Prime: omit broken hero-image area and lower broken image
  14:(0.0,0.45,1.0,1.00),       # Steve Blank: article title and body, excluding the long sidebar
  15:(0.0,0.00,1.0,0.64),       # NITI CRL section/table
  17:(0.0,0.42,1.0,1.00),       # NITI identifying-gaps table
  18:(0.0,0.00,1.0,0.58),       # Innosuisse start-up coaching top half
  27:(0.0,0.00,1.0,0.62),       # Micol regression table at the top of the direct PDF page
  30:(0.0,0.00,1.0,0.68),       # Chen: full-width relationship/playmaker discussion
  35:(0.0,0.00,1.0,0.62),       # NITI TRL table
}
FULL={
  2:(1,0), 3:(16,0), 7:(2,0), 9:(3,0), 12:(1,0), 19:(2,0),
  20:(21,0),21:(2,0),22:(1,0),23:(2,0),24:(3,0),33:(3,0),34:(21,0),36:(3,0)
}
# Use the manually inspected clean captures for the two already corrected slides.
COPY_LOCAL={6:r'C:\Dev\CyberZen\.hermes\plans\redo_slides_7_8\slide_08_capatina_clean_v8.png',26:r'C:\Dev\CyberZen\.hermes\plans\redo_slides_7_8\slide_08_capatina_clean_v8.png'}
# Slide 7 and data slide 28: correctly oriented rotated Seitz table.
ROTATED={5:(32,90),28:(32,90)}
# Full-width text crops where the default bbox was cutting the left/right edge.
WIDE={8:(19,0),10:(54,0),14:(8,0),16:(8,0),22:(1,0),29:(19,0),37:(54,0)}


def normalize(s):
    return re.sub(r'\s+',' ',s.replace('\ufffe','').replace('\ufffd','').replace('\u00ad','')).strip()

def compact_stream(tp):
    chars=[]; idx=[]
    for i in range(tp.count_chars()):
        try:c=tp.get_text_range(i,1)
        except:c=''
        if c in ('\r','\n','\t','\x00','\ufffe','\ufffd','\u00ad'):continue
        chars.append(c);idx.append(i)
    return ''.join(chars),idx

def locate(page,q):
    tp=page.get_textpage();s,idx=compact_stream(tp);q=normalize(q)
    pos=normalize(s).lower().find(q.lower())
    if pos<0:
        pos=re.sub(r'\s+','',s).lower().find(re.sub(r'\s+','',q).lower())
    if pos<0:return None
    u=None
    for k in range(pos,pos+len(re.sub(r'\s+','',q))):
        if k>=len(idx):break
        try:b=tp.get_charbox(idx[k])
        except:b=None
        if b:
            l,y1,r,y2=b
            u=[l,y1,r,y2] if u is None else [min(u[0],l),min(u[1],y1),max(u[2],r),max(u[3],b[3])]
    return u

def full_render(path,pn,scale=3,rotation=0):
    d=pdfium.PdfDocument(str(path)); im=d[pn-1].render(scale=scale,rotation=rotation).to_pil().convert('RGB');d.close();return im

def region_render(path,pn,frac,scale=3):
    d=pdfium.PdfDocument(str(path)); im=d[pn-1].render(scale=scale).to_pil().convert('RGB');d.close()
    w,h=im.size; x0,y0,x1,y1=frac; return im.crop((int(w*x0),int(h*y0),int(w*x1),int(h*y1)))

def wide_bbox(path,pn,q,scale=4):
    d=pdfium.PdfDocument(str(path));pg=d[pn-1];pw,ph=pg.get_size();b=locate(pg,q)
    if not b: d.close();raise RuntimeError('quote not found')
    _,y1,_,y2=b; bottom=min(y1,y2);top=max(y1,y2);top_img=ph-top;bottom_img=ph-bottom
    im=pg.render(scale=scale).to_pil().convert('RGB');d.close();w,h=im.size
    return im.crop((0,max(0,int((top_img-60)*scale)),w,min(h,int((bottom_img+200)*scale))))

def default_bbox(path,pn,q,scale=4):
    d=pdfium.PdfDocument(str(path));pg=d[pn-1];pw,ph=pg.get_size();b=locate(pg,q)
    if not b:d.close();raise RuntimeError('quote not found')
    x1,y1,x2,y2=b;bottom=min(y1,y2);top=max(y1,y2);top_img=ph-top;bottom_img=ph-bottom
    # give the entire relevant column rather than a narrow text-box strip
    left=max(0,x1-24);right=min(pw,x2+145 if x1>pw*.42 else x2+60)
    im=pg.render(scale=scale).to_pil().convert('RGB');d.close()
    return im.crop((int(left*scale),max(0,int((top_img-70)*scale)),int(right*scale),min(im.height,int((bottom_img+190)*scale))))

for n,item in enumerate(items,1):
    outname=f'source_{n:02d}.png';dest=OUT/outname
    if n in COPY_LOCAL:
        shutil.copy2(COPY_LOCAL[n],dest);print('COPY',n,dest);continue
    basename=LOCAL_FILE_OVERRIDES.get(n,os.path.basename(item.get('source_file',item.get('file',''))))
    path=SRC/basename
    if n in ROTATED:
        pn,rot=ROTATED[n];im=full_render(path,pn,scale=3,rotation=rot)
    elif n in REGIONS:
        im=region_render(path,PAGE_OVERRIDES.get(n,item['page']),REGIONS[n],scale=3)
    elif n in FULL:
        pn,rot=FULL[n];im=full_render(path,PAGE_OVERRIDES.get(n,pn),scale=3,rotation=rot)
    elif n in WIDE:
        im=wide_bbox(path,PAGE_OVERRIDES.get(n,item['page']),item['query'])
    else:
        im=default_bbox(path,PAGE_OVERRIDES.get(n,item['page']),item['query'])
    im.save(dest,optimize=True);print('OK',n,im.size)
# Preserve original metadata but point images to v3.
out=[]
for n,item in enumerate(items,1):out.append({**item,'file_out':f'source_{n:02d}.png','source_file_local':LOCAL_FILE_OVERRIDES.get(n,os.path.basename(item.get('source_file',item.get('file',''))))})
(OUT/'manifest.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
print('DONE',len(out))
