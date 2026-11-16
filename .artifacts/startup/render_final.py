from pathlib import Path
import pypdfium2 as pdf
from PIL import Image,ImageOps,ImageDraw
for name in ['questionnaire']:
 r=Path('.artifacts/startup')/(name+'-pages');r.mkdir(exist_ok=True)
 d=pdf.PdfDocument('.artifacts/startup/'+name+'.pdf');print(name,len(d))
 for i,p in enumerate(d):p.render(scale=1.25).to_pil().save(r/f'page-{i+1}.png')
 imgs=[Image.open(p).convert('RGB') for p in r.glob('*.png')]
 thumbs=[]
 for im in imgs:
  im.thumbnail((390,560));thumbs.append(im)
 sheet=Image.new('RGB',(390*3,590*((len(imgs)+2)//3)),'#dddddd')
 for i,im in enumerate(thumbs):sheet.paste(im,((i%3)*390,(i//3)*590))
 sheet.save('.artifacts/startup/'+name+'-montage.png')
