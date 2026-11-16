from zipfile import ZipFile
from pathlib import Path
from lxml import etree as E
import hashlib,json
r=Path('.artifacts/startup');s=next((r/'source').glob('1_*'));f=Path('output/startup/Анкета_Запруднов_ФС.docx')
with ZipFile(s) as a,ZipFile(f) as b:
 changes=[n for n in a.namelist() if a.read(n)!=b.read(n)]
 print('Changed parts:',changes)
 assert changes==['word/document.xml']
 ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
 x=E.fromstring(b.read('word/document.xml')); t=' '.join(x.xpath('//w:t/text()',namespaces=ns))
 assert 'Укажите' not in t and 'Выберите' not in t
 assert '+7 977 381-80-87' in t and 'zaprudnovfedor@gmail.com' in t
 print('Personal data and template preservation checked')
for p in Path('output/startup').glob('*'):print(p.name,p.stat().st_size)
