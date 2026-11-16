import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const r='C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1105-1297-0_26.1105.1297.0_x64__3k8sg7r9htsxt/dependencies';
const {PresentationFile,FileBlob}=await import(pathToFileURL(r+'/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs').href);
const p=await PresentationFile.importPptx(await FileBlob.load('output/startup/Презентация_Запруднов_ФС.pptx'));
await fs.mkdir('.artifacts/startup/final-slides',{recursive:true});
for(let i=0;i<p.slides.items.length;i++){const b=await p.export({slide:p.slides.items[i],format:'png',scale:1});await fs.writeFile('.artifacts/startup/final-slides/slide-'+(i+1)+'.png',new Uint8Array(await b.arrayBuffer()));}
console.log('Rendered',p.slides.items.length);
