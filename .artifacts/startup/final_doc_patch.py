from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED
from lxml import etree as E
f=Path('output/startup/Анкета_Запруднов_ФС.docx');n={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'};W='{'+n['w']+'}'
with ZipFile(f) as z:d={i.filename:z.read(i.filename) for i in z.infolist()}
e=E.fromstring(d['word/document.xml']);rows=e.findall('.//w:tr',n)
for p in rows[14].findall('.//w:p',n):
 pr=p.find('w:pPr',n)
 if pr is None:pr=E.SubElement(p,W+'pPr')
 E.SubElement(pr,W+'keepNext')
for t in e.findall('.//w:t',n):
 if t.text:t.text=t.text.replace('В коде реализованы создание и объединение обращений','Система поддерживает создание и объединение обращений')
d['word/document.xml']=E.tostring(e,xml_declaration=True,encoding='UTF-8',standalone=True)
with ZipFile(f,'w',ZIP_DEFLATED) as z:
 for k,v in d.items():z.writestr(k,v)
print('refined')
