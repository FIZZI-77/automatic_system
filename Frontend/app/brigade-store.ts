export type BrigadeRecord = { id:string; department_id:string; name:string; description:string; specialization:string; status:string };

export const defaultBrigades: BrigadeRecord[] = [
  {id:"b-14",department_id:"dep-utilities",name:"Аварийная бригада №14",description:"Аварийные выезды",specialization:"Водоснабжение",status:"AVAILABLE"},
  {id:"b-07",department_id:"dep-roads",name:"Бригада №7",description:"Обслуживание городской сети",specialization:"Освещение",status:"BUSY"},
];

const key="city-services-brigades";
export function loadBrigades():BrigadeRecord[]{if(typeof window==="undefined")return defaultBrigades;try{const value=JSON.parse(localStorage.getItem(key)||"null");return Array.isArray(value)?value as BrigadeRecord[]:defaultBrigades}catch{return defaultBrigades}}
export function publishBrigades(brigades:BrigadeRecord[]){if(typeof window==="undefined")return;localStorage.setItem(key,JSON.stringify(brigades));window.dispatchEvent(new CustomEvent("city-brigades-changed",{detail:brigades}))}

export function brigadeDisplayName(brigadeId:string){
  return loadBrigades().find(brigade=>brigade.id===brigadeId)?.name||`Городская бригада ${brigadeId.slice(0,8)}`;
}

const vehicleNames:Record<string,string>={
  "55555555-5555-5555-5555-555555555555":"Дорожная машина №14-1",
  "55555555-5555-5555-5555-555555555556":"Аварийная машина №7-1",
  "55555555-5555-5555-5555-555555555557":"Резервная машина №3-1",
  "v-14-1":"Аварийная машина №14-1",
  "v-14-2":"Аварийная машина №14-2",
  "v-14-3":"Аварийная машина №14-3",
  "v-07-1":"Дорожная машина №7-1",
  "v-07-2":"Дорожная машина №7-2",
};

export function vehicleDisplayName(vehicleId:string){
  return vehicleNames[vehicleId]||`Служебная машина ${vehicleId.slice(0,8)}`;
}
