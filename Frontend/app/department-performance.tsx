"use client";

import { useEffect, useState } from "react";
import { api, config, type Session } from "./api";

type Performance = {
  department_id:string;
  created:number;
  completed:number;
  canceled:number;
  active:number;
  completion_rate:number;
  average_response_seconds:number;
  average_resolution_seconds:number;
  response_sample_count:number;
  resolution_sample_count:number;
  response_sla_sample_count:number;
  response_sla_breaches:number;
  average_response_sla_deviation_seconds:number;
  resolution_sla_sample_count:number;
  resolution_sla_breaches:number;
  average_resolution_sla_deviation_seconds:number;
  feedback_count:number;
  average_rating:number;
  positive_rating_rate:number;
  resolved_feedback_rate:number;
  feedback_response_rate:number;
};

type Report = { departments:Performance[]; organization:Performance };

function percent(value:number=0){return `${value.toFixed(1)}%`}
function duration(seconds:number=0){
  if(seconds<60)return `${Math.round(seconds)} сек`;
  if(seconds<3600)return `${Math.round(seconds/60)} мин`;
  return `${(seconds/3600).toFixed(1)} ч`;
}
function deviation(seconds:number=0){return `${seconds>0?"+":""}${duration(Math.abs(seconds))}${seconds>0?" позже":seconds<0?" раньше":""}`}

export function DepartmentPerformanceSection({period,session,onNotice}:{period:number;session:Session;onNotice:(text:string)=>void}){
  const [report,setReport]=useState<Report>();
  const [names,setNames]=useState<Record<string,string>>({});

  useEffect(()=>{
    if(session.accessToken==="demo")return;
    let active=true;
    const to=new Date(),from=new Date();
    from.setDate(to.getDate()-period+1);
    const filter={from:from.toISOString(),to:to.toISOString()};
    api<Report>(config.endpoints.analyticsDepartmentPerformance,{filter},"POST",session.accessToken)
      .then(value=>{if(active)setReport(value)})
      .catch(error=>{if(active)onNotice(error instanceof Error?error.message:"Не удалось загрузить отчёт по департаментам")});
    api<{departments:Array<{id:string;name:string}>}>(config.endpoints.departmentsList,{limit:100,offset:0},"POST",session.accessToken)
      .then(value=>{if(active)setNames(Object.fromEntries((value.departments||[]).map(item=>[item.id,item.name])))})
      .catch(()=>{});
    return()=>{active=false};
  },[onNotice,period,session.accessToken]);

  const rows=report?.departments||[];
  const organization=report?.organization;
  return <section className="analytics-section department-performance"><div className="analytics-section-head"><div><span className="eyebrow">Качество услуг</span><h3>Работа департаментов</h3></div><b>Заявки, созданные за {period} дней</b></div>
    <p>Оценки оставляют авторы завершённых заявок. Отклонение SLA: положительное значение означает просрочку, отрицательное — выполнение раньше срока.</p>
    <div className="department-performance-table"><table><thead><tr><th>Департамент</th><th>Заявки</th><th>Выполнено</th><th>Оценка</th><th>Проблема решена</th><th>Реакция SLA</th><th>Выполнение SLA</th><th>Средняя реакция</th><th>Среднее выполнение</th><th>Отклонение реакции</th><th>Отклонение выполнения</th></tr></thead><tbody>
      {organization&&<PerformanceRow title="Организация" value={organization} total/>}
      {rows.map(value=><PerformanceRow key={value.department_id} title={names[value.department_id]||value.department_id} value={value}/>)}
    </tbody></table></div>
    {!rows.length&&<p className="analytics-empty">За выбранный период данных нет.</p>}
    <small>Доли SLA рассчитаны по заявкам с событиями, содержащими фактическое время и дедлайн. Количество таких заявок показано рядом с процентом.</small>
  </section>;
}

function PerformanceRow({title,value,total=false}:{title:string;value:Performance;total?:boolean}){
  const responseSLA=value.response_sla_sample_count?percent((value.response_sla_sample_count-value.response_sla_breaches)/value.response_sla_sample_count*100):"—";
  const resolutionSLA=value.resolution_sla_sample_count?percent((value.resolution_sla_sample_count-value.resolution_sla_breaches)/value.resolution_sla_sample_count*100):"—";
  return <tr className={total?"total":""}><th>{title}</th><td>{value.created||0} <small>{value.active||0} открыто · {value.canceled||0} отменено</small></td><td>{value.completed||0} <small>{percent(value.completion_rate)}</small></td><td>{value.feedback_count?`${value.average_rating.toFixed(2)} / 5`:"—"}<small>{value.feedback_count||0} оценок · {percent(value.positive_rating_rate)} положительных · отклик {percent(value.feedback_response_rate)}</small></td><td>{value.feedback_count?percent(value.resolved_feedback_rate):"—"}<small>{value.feedback_count||0} ответов</small></td><td>{responseSLA}<small>{value.response_sla_sample_count||0} измерений</small></td><td>{resolutionSLA}<small>{value.resolution_sla_sample_count||0} измерений</small></td><td>{value.response_sample_count?duration(value.average_response_seconds):"—"}<small>{value.response_sample_count||0} измерений</small></td><td>{value.resolution_sample_count?duration(value.average_resolution_seconds):"—"}<small>{value.resolution_sample_count||0} измерений</small></td><td>{value.response_sla_sample_count?deviation(value.average_response_sla_deviation_seconds):"—"}</td><td>{value.resolution_sla_sample_count?deviation(value.average_resolution_sla_deviation_seconds):"—"}</td></tr>;
}
