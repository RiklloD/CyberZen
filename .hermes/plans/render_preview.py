import pypdfium2 as pdfium, os
pdf=r'C:\Dev\CyberZen\.hermes\plans\clean_deck_verify.pdf'
out=r'C:\Dev\CyberZen\.hermes\plans\clean_deck_preview'
os.makedirs(out,exist_ok=True)
d=pdfium.PdfDocument(pdf)
for pn in [1,2,3,14,29,42]:
    page=d[pn-1]
    page.render(scale=1.3).to_pil().convert('RGB').save(os.path.join(out,f'slide_{pn:02d}.png'))
    print('rendered',pn,page.get_size())
d.close()
