from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
import json, math
root=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v2')
items=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
font=ImageFont.truetype(r'C:\Windows\Fonts\arial.ttf',18)
small=ImageFont.truetype(r'C:\Windows\Fonts\arial.ttf',13)
for gi in range(5):
    batch=items[gi*6:(gi+1)*6]
    if not batch:break
    W,H=720,430
    sheet=Image.new('RGB',(W*3,H*2),(240,243,247));d=ImageDraw.Draw(sheet)
    for j,it in enumerate(batch):
        im=Image.open(root/it['file_out']).convert('RGB')
        im.thumbnail((W-20,H-50),Image.Resampling.LANCZOS)
        x=(j%3)*W+(W-im.width)//2; y=(j//3)*H+34
        sheet.paste(im,(x,y))
        d.text(((j%3)*W+12,(j//3)*H+8),f"#{gi*6+j+1}  {it['key'][1][:50]}",fill=(20,35,55),font=small)
    out=root/f'contact_{gi+1}.png';sheet.save(out,optimize=True);print(out)
