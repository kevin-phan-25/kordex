'use client'

import {Activity} from 'lucide-react'
import {useRouter} from 'next/navigation'
import {useEffect} from 'react'

export function LiveRefresh({enabled,intervalMs=10000}:{enabled:boolean;intervalMs?:number}) {
  const router=useRouter()

  useEffect(()=>{
    if(!enabled)return
    const timer=window.setInterval(()=>{
      if(document.visibilityState==='visible')router.refresh()
    },intervalMs)
    return ()=>window.clearInterval(timer)
  },[enabled,intervalMs,router])

  if(!enabled)return null
  return <span className="status teal" role="status" aria-live="polite"><Activity size={12}/>Live · refreshes every {Math.round(intervalMs/1000)}s</span>
}
