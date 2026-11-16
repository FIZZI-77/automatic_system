import importlib.util
for x in ['pypdfium2','PIL','docx','pdf2image']: print(x,bool(importlib.util.find_spec(x)))
from zipfile import ZipFile
from pathlib import Path
from lxml import etree as E
f=next(Path('.artifacts/startup/source').glob('1_*'))
with ZipFile(f) as z:
 n={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
 e=E.fromstring(z.read('word/document.xml'))
 print('fonts',e.xpath('//w:rFonts/@w:ascii',namespaces=n)); print('sizes',e.xpath('//w:sz/@w:val',namespaces=n)[:30]); print('rowheight',e.xpath('//w:trHeight/@w:hRule',namespaces=n))
