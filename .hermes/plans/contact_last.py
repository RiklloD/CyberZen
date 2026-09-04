from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
import json
root=Path(r'C:\Dev\CyberZen\.hermes\plans\source_shots_v2')
items=json.loads((root/'manifest.json').read_text(encoding='utf-8'))[30:]
W,H=960,530
sheet=Image.new('RGB',(W*2,H*4),(240,243,247));d=ImageDraw.Draw(sheet)
small=ImageFont.truetype(r'C:\Windows\Fonts\arial.ttf',16)
for j,it in enumerate(items):
 im=Image.open(root/it['file_out']).convert('RGB'); im.thumbnail((W-20,H-50),Image.Resampling.LANCZOS)
 x=(j%2)*W+(W-im.width)//2;y=(j//2)*H+34;sheet.paste(im,(x,y));d.text(((j%2)*W+12,(j//2)*H+8),f"#{31+j} {it['key'][1][:60]}",fill=(20,35,55),font=small)
out=root/'contact_last.png';sheet.save(out,optimize=True);print(out)
