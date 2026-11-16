from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
import pypdf
r=Path('.artifacts/startup/source'); ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main','a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
for f in r.iterdir():
 if f.name.startswith(('1_','3_','8_')):
  with ZipFile(f) as z:
   if f.suffix=='.docx':
    e=E.fromstring(z.read('word/document.xml'))
    if f.name.startswith('1_'):
     for i,tr in enumerate(e.findall('.//w:tr',ns)):
      print('ROW',i,[[ ''.join(p.itertext()) for p in []] or ' / '.join(c.xpath('.//w:t/text()',namespaces=ns)) for c in tr.findall('w:tc',ns)])
     print('SECTION',E.tostring(e.find('.//w:sectPr',ns)).decode())
    else:
     txt='\n'.join(e.xpath('//w:t/text()',namespaces=ns)); Path('.artifacts/startup/priorities.txt').write_text(txt,encoding='utf8'); print('PRIORITY MATCHES', '\n'.join(x for x in txt.splitlines() if any(s in x.lower() for s in ['экономик','цифров','управлен','другое'])))
   else:
    print('SIZE',z.read('ppt/presentation.xml').decode()[:900])
    for i in [1,2,3,4,5,6,7,8]:
     e=E.fromstring(z.read(f'ppt/slides/slide{i}.xml'));print('SLIDE',i)
     for sp in e.findall('.//p:sp',ns):
      print(sp.xpath('.//a:t/text()',namespaces=ns),[E.tostring(x).decode() for x in sp.findall('.//a:xfrm',ns)])
 forpdf=False
 if f.suffix=='.pdf':
  d=pypdf.PdfReader(f);print('PDF',f.name,len(d.pages)); print(''.join(p.extract_text() for p in d.pages)[:14000])

