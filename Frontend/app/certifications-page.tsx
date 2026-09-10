"use client";
/* eslint-disable react-hooks/set-state-in-effect */

import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, config, Session } from "./api";
import { qualificationLabel, qualificationStateClass } from "./qualification-labels";

type Notice=(message:string)=>void;
type Profile={work_profile:{id:string;position:string;status:string};user_profile:{full_name:string}};
type CertType={id:string;name:string;code:string;requires_file:boolean};
type Certification={id:string;certification_type_id:string;certificate_number?:string;issuer?:string;status:string;issued_at?:number;expires_at?:number};
type Grant={id:string;skill_id:string;proficiency_level?:string;source_type:string;active:boolean};
type Skill={id:string;name:string};

export function CertificationsPage({session,onNotice}:{session:Session;onNotice:Notice}){
  const demo=session.accessToken==="demo";
  const [profiles,setProfiles]=useState<Profile[]>([]);
  const [types,setTypes]=useState<CertType[]>([]);
  const [skills,setSkills]=useState<Skill[]>([]);
  const [selected,setSelected]=useState<Profile>();
  const [certifications,setCertifications]=useState<Certification[]>([]);
  const [grants,setGrants]=useState<Grant[]>([]);
  const [modal,setModal]=useState<"certificate"|"skill"|null>(null);

  const load=useCallback(async()=>{
    if(demo){
      setProfiles([
        {work_profile:{id:"work-demo-1",position:"Мастер дорожных работ",status:"ACTIVE"},user_profile:{full_name:"Алексей Смирнов"}},
        {work_profile:{id:"work-demo-2",position:"Аварийный техник",status:"ON_SHIFT"},user_profile:{full_name:"Ирина Волкова"}},
      ]);
      setTypes([
        {id:"cert-demo-1",name:"Безопасность дорожных работ",code:"ROAD_CERT",requires_file:true},
        {id:"cert-demo-2",name:"Допуск к электроустановкам",code:"ELECTRIC_CERT",requires_file:true},
      ]);
      setSkills([
        {id:"skill-demo-1",name:"Ремонт дорожного покрытия"},
        {id:"skill-demo-2",name:"Аварийный ремонт водопровода"},
      ]);
      return;
    }
    try{
      const [profileResult,typeResult,skillResult]=await Promise.all([
        api<{work_profiles:Profile[]}>(config.endpoints.workProfilesList,{limit:100,offset:0},"POST",session.accessToken),
        api<{certification_types:CertType[]}>(config.endpoints.certificationTypesList,{active:true,limit:100,offset:0},"POST",session.accessToken),
        api<{skills:Skill[]}>(config.endpoints.skillsList,{active:true,limit:100,offset:0},"POST",session.accessToken),
      ]);
      setProfiles(profileResult.work_profiles||[]);
      setTypes(typeResult.certification_types||[]);
      setSkills(skillResult.skills||[]);
    }catch(error){onNotice(error instanceof Error?error.message:"Не удалось загрузить удостоверения")}
  },[demo,onNotice,session.accessToken]);
  useEffect(()=>{void load()},[load]);

  async function open(profile:Profile){
    setSelected(profile);
    if(demo){
      const road=profile.work_profile.id==="work-demo-1";
      setCertifications([{id:`cert-${profile.work_profile.id}`,certification_type_id:road?"cert-demo-1":"cert-demo-2",certificate_number:road?"ДР-2026-014":"ЭБ-2026-077",issuer:road?"Учебный центр городских служб":"МосЭнергоОбучение",status:road?"VERIFIED":"PENDING"}]);
      setGrants([{id:`grant-${profile.work_profile.id}`,skill_id:road?"skill-demo-1":"skill-demo-2",proficiency_level:road?"Эксперт":"Старший специалист",source_type:"MANUAL",active:true}]);
      return;
    }
    const [certResult,grantResult]=await Promise.all([
      api<{certifications:Certification[]}>(config.endpoints.workProfileCertificationsList,{work_profile_id:profile.work_profile.id,limit:100,offset:0},"POST",session.accessToken),
      api<{skill_grants:Grant[]}>(config.endpoints.workProfileSkillsList,{work_profile_id:profile.work_profile.id},"POST",session.accessToken),
    ]);
    setCertifications(certResult.certifications||[]);
    setGrants(grantResult.skill_grants||[]);
  }

  async function upload(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!selected)return;
    const form=new FormData(event.currentTarget),issued=String(form.get("issued_at")||""),expires=String(form.get("expires_at")||"");
    let certificateFileId:string|undefined;
    const file=form.get("file");
    if(!demo&&file instanceof File&&file.size){
      const created=await api<{file:{id:string};upload_url:string}>(config.endpoints.filesUploadCreate,{name:file.name,content_type:file.type||"application/octet-stream",size:file.size},"POST",session.accessToken);
      const uploaded=await fetch(created.upload_url,{method:"PUT",headers:{"Content-Type":file.type||"application/octet-stream"},body:file});
      if(!uploaded.ok)throw new Error("Не удалось загрузить файл удостоверения");
      await api(config.endpoints.filesUploadConfirm,{file_id:created.file.id},"POST",session.accessToken);
      certificateFileId=created.file.id;
    }
    if(demo){
      setCertifications(current=>[...current,{id:`cert-demo-${Date.now()}`,certification_type_id:String(form.get("type_id")),certificate_number:String(form.get("number")),issuer:String(form.get("issuer")),status:"PENDING"}]);
    }else{
      await api(config.endpoints.workProfileCertificationsUpload,{work_profile_id:selected.work_profile.id,certification_type_id:String(form.get("type_id")),certificate_number:String(form.get("number")),issuer:String(form.get("issuer")),issued_at:issued?new Date(issued).toISOString():undefined,expires_at:expires?new Date(expires).toISOString():undefined,certificate_file_id:certificateFileId},"POST",session.accessToken);
      await open(selected);
    }
    setModal(null);
    onNotice("Удостоверение добавлено и ожидает проверки");
  }

  async function grantSkill(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!selected)return;
    const form=new FormData(event.currentTarget),skillId=String(form.get("skill_id"));
    if(demo){
      setGrants(current=>[...current,{id:`grant-demo-${Date.now()}`,skill_id:skillId,proficiency_level:String(form.get("level")),source_type:"MANUAL",active:true}]);
    }else{
      await api(config.endpoints.workProfileSkillsGrant,{work_profile_id:selected.work_profile.id,skill_id:skillId,proficiency_level:String(form.get("level")),reason:String(form.get("reason"))},"POST",session.accessToken);
      await open(selected);
    }
    setModal(null);
    onNotice("Навык добавлен сотруднику");
  }

  async function action(item:Certification,kind:"verify"|"reject"){
    if(demo){setCertifications(current=>current.map(cert=>cert.id===item.id?{...cert,status:kind==="verify"?"VERIFIED":"REJECTED"}:cert))}
    else{
      const endpoint=kind==="verify"?config.endpoints.workProfileCertificationsVerify:config.endpoints.workProfileCertificationsReject;
      const payload=kind==="verify"?{id:item.id}:{id:item.id,rejection_reason:"Отклонено администратором"};
      await api(endpoint,payload,"POST",session.accessToken);
      if(selected)await open(selected);
    }
    onNotice("Статус удостоверения обновлён");
  }
  async function removeCertification(item:Certification){
    if(demo)setCertifications(current=>current.filter(cert=>cert.id!==item.id));
    else{await api(config.endpoints.workProfileCertificationsRevoke,{id:item.id,reason:"Удалено администратором"},"POST",session.accessToken);if(selected)await open(selected)}
    onNotice("Удостоверение удалено у сотрудника");
  }
  async function removeGrant(item:Grant){
    if(demo)setGrants(current=>current.filter(grant=>grant.id!==item.id));
    else{await api(config.endpoints.workProfileSkillsRevoke,{id:item.id,reason:"Удалено администратором"},"POST",session.accessToken);if(selected)await open(selected)}
    onNotice("Навык удалён у сотрудника");
  }
  async function expire(){
    const result=demo?{expired_certifications:[]}:await api<{expired_certifications:Certification[]}>(config.endpoints.workProfileCertificationsExpire,{limit:500},"POST",session.accessToken);
    if(selected&&!demo)await open(selected);
    onNotice(`Обработано просроченных удостоверений: ${result.expired_certifications?.length||0}`);
  }

  return <section className="ops-page qualification-page">
    <div className="ops-head"><div><span className="eyebrow">Profile Service</span><h2>Удостоверения и допуски</h2><p>Добавление, проверка и удаление удостоверений и навыков сотрудников.</p></div><div><button className="ghost" onClick={()=>void expire()}>Обработать просроченные</button><button className="ghost" disabled={!selected} onClick={()=>setModal("skill")}>+ Навык</button><button className="primary" disabled={!selected} onClick={()=>setModal("certificate")}>+ Удостоверение</button></div></div>
    <div className={`ops-layout ${selected?"selected":""}`}>
      <div className="people-qualification-list">{profiles.map(profile=><button key={profile.work_profile.id} className={selected?.work_profile.id===profile.work_profile.id?"selected":""} onClick={()=>void open(profile)}><b>{profile.user_profile.full_name}</b><span>{profile.work_profile.position}</span><em className={`ops-state ${qualificationStateClass(profile.work_profile.status)}`}>{qualificationLabel(profile.work_profile.status)}</em></button>)}</div>
      {selected&&<aside className="ops-detail certification-detail"><button className="detail-close" onClick={()=>setSelected(undefined)}>×</button><span className="eyebrow">Допуски сотрудника</span><h2>{selected.user_profile.full_name}</h2><div className="qualification-subhead"><h3>Удостоверения</h3><button className="ghost small" onClick={()=>setModal("certificate")}>+ Добавить</button></div>{certifications.length?certifications.map(item=><div className="cert-row" key={item.id}><div><b>{types.find(type=>type.id===item.certification_type_id)?.name||item.certification_type_id}</b><small>{item.certificate_number||"Без номера"} · {item.issuer||"Организация не указана"}</small><em className={`ops-state ${qualificationStateClass(item.status)}`}>● {qualificationLabel(item.status)}</em></div><div className="certification-actions">{item.status==="PENDING"&&<><button onClick={()=>void action(item,"verify")}>Подтвердить</button><button onClick={()=>void action(item,"reject")}>Отклонить</button></>}{["PENDING","VERIFIED"].includes(item.status)&&<button className="danger-action" onClick={()=>void removeCertification(item)}>Удалить</button>}</div></div>):<p className="ops-empty">Удостоверений нет.</p>}<div className="qualification-subhead"><h3>Действующие навыки</h3><button className="ghost small" onClick={()=>setModal("skill")}>+ Добавить</button></div>{grants.filter(item=>item.active).length?grants.filter(item=>item.active).map(item=><div className="cert-row" key={item.id}><div><b>{skills.find(skill=>skill.id===item.skill_id)?.name||item.skill_id}</b><small>{item.proficiency_level||"Уровень не задан"} · {qualificationLabel(item.source_type)}</small></div><button className="danger-action" onClick={()=>void removeGrant(item)}>Удалить</button></div>):<p className="ops-empty">Активных навыков нет.</p>}</aside>}
    </div>
    {modal==="certificate"&&selected&&<div className="ops-modal" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setModal(null)}}><form className="ops-modal-card ops-form" role="dialog" aria-modal="true" onSubmit={upload}><button type="button" className="modal-close" onClick={()=>setModal(null)}>×</button><span className="eyebrow">Новое удостоверение</span><h2>{selected.user_profile.full_name}</h2><label>Тип<select name="type_id" required>{types.map(type=><option key={type.id} value={type.id}>{type.name}{type.requires_file?" · нужен файл":""}</option>)}</select></label><label>Номер<input name="number" required/></label><label>Кем выдано<input name="issuer" required/></label><div><label>Дата выдачи<input name="issued_at" type="date"/></label><label>Действует до<input name="expires_at" type="date"/></label></div><label>Файл удостоверения<input name="file" type="file" accept="image/*,.pdf"/></label><button className="primary">Добавить удостоверение</button></form></div>}
    {modal==="skill"&&selected&&<div className="ops-modal" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget)setModal(null)}}><form className="ops-modal-card ops-form" role="dialog" aria-modal="true" onSubmit={grantSkill}><button type="button" className="modal-close" onClick={()=>setModal(null)}>×</button><span className="eyebrow">Новый навык</span><h2>{selected.user_profile.full_name}</h2><label>Навык<select name="skill_id" required>{skills.map(skill=><option key={skill.id} value={skill.id}>{skill.name}</option>)}</select></label><label>Уровень владения<input name="level" placeholder="Например: эксперт" required/></label><label>Основание<textarea name="reason" rows={3} required/></label><button className="primary">Добавить навык</button></form></div>}
  </section>;
}
