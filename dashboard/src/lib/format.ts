export const date=(value?:string|null)=>value?new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(value)):'—'
export const relative=(value?:string|null)=>{if(!value)return 'No report yet';const seconds=Math.max(0,(Date.now()-new Date(value).getTime())/1000);if(seconds<60)return `${Math.floor(seconds)} sec ago`;if(seconds<3600)return `${Math.floor(seconds/60)} min ago`;if(seconds<86400)return `${Math.floor(seconds/3600)} hr ago`;return `${Math.floor(seconds/86400)} days ago`}
export const shortID=(value:string)=>`${value.slice(0,8)}…${value.slice(-4)}`
export const human=(value:string)=>value.replaceAll('_',' ').replace(/([a-z])([A-Z])/g,'$1 $2').replace(/^./,x=>x.toUpperCase())
export function queryString(values:Record<string,string|number|undefined>){const q=new URLSearchParams();for(const [k,v] of Object.entries(values))if(v!==undefined&&v!=='')q.set(k,String(v));return q.toString()}
