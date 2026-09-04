import pypdfium2 as pdfium, os, glob, re
files = {}
# direct thesis PDFs
for p in glob.glob(r'G:\Mon Drive\ZHermes Agent\Bachelor Thesis\literature\papers\*.pdf'):
    files[os.path.basename(p)] = p
# downloaded real sources
for p in glob.glob(r'C:\Users\lorik\AppData\Local\Temp\realsrc\*.pdf'):
    files[os.path.basename(p)] = p
terms = [
    'knowledge infrastructure','talent pools','formal institutions','close business relationships','customer introductions',
    'I-Corps','customer discovery','market features','0.514','0.310','commercial sphere','day one','business advisor','technology advisor',
    '35% more time','48% more capital','12 defining attributes','5–15','5-15',
    'TRL 1','TRL 5','Commercial Readiness','CRL','initial opportunities','No peer-reviewed','Innosuisse','BRIDGE','20.7','17.6','57%','70%',
    'EIC Accelerator','Pathfinder','Switzerland','CERN','Venture Connect','0% equity','Deep Tech','spinout value','100',
]
for term in terms:
    print('\n### TERM', term)
    hits=0
    for name,path in files.items():
        try: d=pdfium.PdfDocument(path)
        except: continue
        for i in range(len(d)):
            try: t=d[i].get_textpage().get_text_bounded()
            except: continue
            if term.lower() in t.lower():
                lines=[re.sub(r'\s+',' ',x).strip() for x in t.splitlines() if x.strip()]
                # show lines around first matching line
                idx=next((j for j,x in enumerate(lines) if term.lower() in x.lower()),0)
                snippet=' | '.join(lines[max(0,idx-1):idx+3])[:500]
                print(name, 'p',i+1, ':', snippet)
                hits += 1
                break
        d.close()
    if hits==0: print('NO HITS')
