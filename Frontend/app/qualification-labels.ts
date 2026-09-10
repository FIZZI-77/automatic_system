const labels:Record<string,string>={
  ACTIVE:"Активен",INACTIVE:"Неактивен",ON_SHIFT:"На смене",OFF_SHIFT:"Не на смене",SUSPENDED:"Приостановлен",
  PENDING:"Ожидает проверки",VERIFIED:"Подтверждено",REJECTED:"Отклонено",EXPIRED:"Просрочено",REVOKED:"Отозвано",
  AVAILABLE:"Доступна",BUSY:"Занята",ON_ROUTE:"В пути",DEGRADED:"Ограниченно доступна",OFFLINE:"Нет связи",ARCHIVED:"В архиве",
  MANUAL:"Назначено вручную",CERTIFICATION:"Получено по удостоверению",
};

export function qualificationLabel(value:unknown){
  const raw=String(value??"").toUpperCase();
  const key=raw.replace("WORK_PROFILE_STATUS_","").replace("CERTIFICATION_STATUS_","").replace("SKILL_GRANT_SOURCE_TYPE_","").replace("BRIGADE_STATUS_","");
  return labels[key]||String(value||"Не указано");
}

export function qualificationStateClass(value:unknown){return String(value||"inactive").toLowerCase().replace(/[^a-z0-9_-]/g,"")}
