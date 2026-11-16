from pathlib import Path
import pypdfium2 as pdf
r=Path('.artifacts/startup/reference-pages');r.mkdir(exist_ok=True)
d=pdf.PdfDocument('.artifacts/startup/reference.pdf')
print('pages',len(d))
for i,p in enumerate(d):p.render(scale=1.15).to_pil().save(r/f'page-{i+1}.png')
