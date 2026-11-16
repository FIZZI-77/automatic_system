from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
import json,pypdf
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
f=next(Path('.artifacts/startup/source').glob('8_*'))
with ZipFile(f) as z:
 for i in range(1,9):
  e=E.fromstring(z.read(f'ppt/slides/slide{i}.xml'));print('SLIDE',i)
  for sp in e.findall('.//p:sp',n):
   t=sp.xpath('.//a:t/text()',namespaces=n)
   if t: print(t,[(x.tag.split('}')[-1],dict(x.attrib)) for x in sp.findall('.//a:xfrm/*',n)],sp.xpath('.//a:rPr/@sz',namespaces=n))
for f in Path('.artifacts/startup/source').glob('*.pdf'):
 d=pypdf.PdfReader(f);t='\n'.join(p.extract_text() for p in d.pages);Path('.artifacts/startup/'+f.name[:1]+'.txt').write_text(t,encoding='utf8');print('PDF',f.name,len(d.pages));print(t[:4500])
