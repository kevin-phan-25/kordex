'use client'
import {useSearchParams} from 'next/navigation'
export function LoginError(){const q=useSearchParams();const value=q.get('error')??'';return <div className="banner error" role="alert">{value==='access_denied'?'Your account has no organization access. Ask an administrator to add your OIDC subject.':value==='configuration'?'Sign in is not configured yet. Set the dashboard OIDC environment values.':'Sign in could not be completed. Please try again.'}</div>}
