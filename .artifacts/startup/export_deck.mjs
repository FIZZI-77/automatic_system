import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const runtime='C:/Program Files/WindowsApps/OpenAI.CodexPrimaryRuntime.v26-1105-1297-0_26.1105.1297.0_x64__3k8sg7r9htsxt/dependencies';
const {Presentation,PresentationFile}=await import(pathToFileURL(runtime+'/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs').href);
const root=process.cwd(), build=path.join(root,'.artifacts/startup');
const spec=JSON.parse(await fs.readFile(path.join(build,'deck-spec.json'),'utf8'));
const presentation=Presentation.create({slideSize:{width:1280,height:720}});
presentation.theme.defaultFont='Arial';
const text=(s,t,x,y,w,h,size=28,bold=false,color='#173B31')=>{let a=s.shapes.add({geometry:'textbox',position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});a.text=t;a.text.style={fontSize:size,typeface:'Arial',bold,color,verticalAlignment:'top'};return a;};
for(let i=0;i<spec.length;i++){
 const d=spec[i],s=presentation.slides.add();s.background.fill='#FAF8F2';
 text(s,'СТУДЕНЧЕСКИЙ СТАРТАП',68,34,900,27,16,true,'#58655F');text(s,d.title,68,i===0?149:93,1140,i===0?278:108,i===0?57:43,true);
 text(s,'Запруднов Фёдор Сергеевич',68,665,900,26,16,false,'#58655F');text(s,String(i+1).padStart(2,'0'),1150,662,64,30,20,true,'#9B5A29');
 if(i===0){text(s,d.lines[0],72,450,1100,64,29,false,'#58655F');text(s,d.lines.slice(1).join('\n'),72,550,1100,98,23);}
 if(i===1){const bytes=await fs.readFile(path.join(root,'Frontend/public/og.png'));s.images.add({blob:bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength),contentType:'image/png',alt:'Иллюстрация из веб-приложения проекта «Город рядом»',position:{left:68,top:211,width:508,height:339},fit:'contain'});text(s,d.lines[0],634,207,562,86,32,true);text(s,d.lines[1],634,315,550,152,28);text(s,d.lines[2],634,489,550,128,26,false,'#58655F');}
 if(d.cols)d.cols.forEach((c,j)=>{const x=j===0?72:672;text(s,c[0],x,217,528,i===6?116:67,i===6&&j===0?42:32,true);text(s,c[1],x,i===6&&j===0?374:302,528,i===6&&j===0?230:322,26);});
 if(i===2)d.rows.forEach((r,j)=>{const y=214+j*103;text(s,String(j+1).padStart(2,'0'),72,y,80,60,39,true,'#9B5A29');text(s,r[0],178,y+2,270,48,29,true);text(s,r[1],479,y+3,703,83,27);});
 if(i===5){text(s,d.lines[0],72,207,1120,98,32,true);d.rows.forEach((r,j)=>{const y=343+j*72;text(s,r[0],72,y,300,50,27,true);text(s,r[1],407,y,786,63,26);});}
 if(i===7){text(s,d.lines[0],72,240,1100,88,43,true);text(s,d.lines[1],72,359,1100,132,33);text(s,d.lines[2],72,532,1100,85,25,false,'#58655F');}
 s.speakerNotes.text='Основание: README.md; Frontend/app/ticket-workspace.tsx; Ticket_Service/src/core/repository/request_repo.go; Dispatch_Service/src/core/service/workflow.go; Routing_Service/src/infrastructure/valhalla/client.go; docs/architecture/code-interactions.md. Документация: локальная Wiki, README сервисов и связанные справочники YouTrack https://automaticsystem.youtrack.cloud/articles/ACS-A-34/Kod-i-funkcii-Ticket-Service и https://automaticsystem.youtrack.cloud/articles/ACS-A-28/Kod-i-funkcii-Dispatch-Service. Иллюстрация: Frontend/public/og.png. Личные сведения предоставлены заявителем.';
}
const candidate=path.join(build,'candidate.pptx');await(await PresentationFile.exportPptx(presentation)).save(candidate);console.log('EXPORTED',candidate);
const skill='C:/Users/Fedor/.codex/plugins/cache/openai-primary-runtime/presentations/26.1110.11613/skills/presentations';
const {finalizePresentation}=await import(pathToFileURL(skill+'/container_tools/artifact_tool_utils.mjs').href);
const result=await finalizePresentation({workspaceDir:root,candidatePath:candidate,finalPath:path.join(root,'output/startup/Презентация_Запруднов_ФС.pptx'),pythonExecutable:runtime+'/python/python.exe',integrityValidatorPath:skill+'/container_tools/inspect_presentation_package_integrity.py',layoutValidatorPath:skill+'/container_tools/inspect_presentation_layout_geometry.py',layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit'],explicitTotalSlideCount:8,fontPolicy:{basis:'design',families:['Arial']},verifyArtifactToolImport:true,receiptPath:path.join(build,'validation.json')});console.log(JSON.stringify(result));
