from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
f=next(Path('.artifacts/startup/source').glob('8_*'))
with ZipFile(f) as z:
 n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main'}
 e=E.fromstring(z.read('ppt/theme/theme1.xml'));print(e.xpath('//a:clrScheme/*/*/@val',namespaces=n));print(e.xpath('//a:latin/@typeface',namespaces=n))
