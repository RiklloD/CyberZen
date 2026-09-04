from PIL import Image,ImageDraw,ImageFont
from pathlib import Path
root=Path(r'C:\Dev\CyberZen\.hermes\plans\deck_v3_preview')
files=sorted(root.glob('slide_*.png'))
W,H=640,360;cols=3;rows=(len(files)+cols-1)//cols
sheet=Image.new('RGB',(W*cols,H*rows),(225,231,238));d=ImageDraw.Draw(sheet);font=ImageFont.truetype(r'C:\Windows\Fonts\arial.ttf',14)
for i,p in enumerate(files):
 im=Image.open(p).convert('RGB');im.thumbnail((W-10,H-30),Image.Resampling.LANCZOS)
 x=(i%cols)*W+(W-im.width)//2;y=(i//cols)*H+24;sheet.paste(im,(x,y));d.text(((i%cols)*W+8,(i//cols)*H+5),p.stem,fill=(20,35,55),font=font)
sheet.save(r'C:\Dev\CyberZen\.hermes\plans\deck_v3_preview\contact.png',optimize=True);print(sheet.size)
