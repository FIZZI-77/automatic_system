from pathlib import Path
from zipfile import ZipFile
from lxml import etree
root=Path('.artifacts/startup/source')
for f in root.iterdir():
 print('\nFILE',f.name)
 if f.suffix in ('.docx','.pptx'):
  with ZipFile(f) as z:
   names=['word/document.xml'] if f.suffix=='.docx' else sorted([n for n in z.namelist() if __import__('re').match(r'ppt/slides/slide\d+.xml$',n)])
   for n in names:
    e=etree.fromstring(z.read(n)); print(n)
    for p in e.xpath('//*[local-name()="p"]'):
     s=''.join(p.xpath('.//*[local-name()="t"]/text()'))
     if s:print(s)
