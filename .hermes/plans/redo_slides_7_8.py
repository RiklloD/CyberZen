#!/usr/bin/env python3
import os
from PIL import Image
import pypdfium2 as pdfium

OUT=r'C:\Dev\CyberZen\.hermes\plans\redo_slides_7_8'
os.makedirs(OUT,exist_ok=True)

def render_region(pdf_path,page_no,region,scale,outfile):
    d=pdfium.PdfDocument(pdf_path); page=d[page_no-1]
    bmp=page.render(scale=scale); im=bmp.to_pil().convert('RGB')
    l,t,r,b=region
    crop=im.crop((int(l*scale),int(t*scale),int(r*scale),int(b*scale)))
    crop.save(os.path.join(OUT,outfile),optimize=True)
    print(outfile,crop.size,os.path.getsize(os.path.join(OUT,outfile)))
    d.close()

# Slide 7: Seitz meta-analysis table. The old crop was a narrow text-bbox strip;
# this keeps the table heading and several comparison rows in the original layout.
seitz=r'C:\Users\lorik\AppData\Local\Temp\realsrc\04_Seitz_2026.pdf'
d=pdfium.PdfDocument(seitz); page=d[31]; w,h=page.get_size(); print('Seitz size',w,h); d.close()
render_region(seitz,32,(0,0,w,360),4.0,'slide_07_seitz_original_table.png')
render_region(seitz,32,(0,0,w,h),3.0,'slide_07_seitz_original_page.png')

# Slide 8: Capatina foresight paper. Keep the full-width original paragraph
# around the structural model and a full-page version for context.
capatina=r'C:\Users\lorik\AppData\Local\Temp\realsrc\capatina_foresight.pdf'
d=pdfium.PdfDocument(capatina); page=d[9]; w,h=page.get_size(); print('Capatina size',w,h); d.close()
render_region(capatina,10,(38,180,w-38,480),4.0,'slide_08_capatina_original_excerpt.png')
render_region(capatina,10,(0,0,w,h),3.0,'slide_08_capatina_original_page.png')
