import type {NextConfig} from 'next'
import {contentSecurityPolicy} from './src/lib/content-security-policy'

const config:NextConfig={poweredByHeader:false,output:'standalone',serverExternalPackages:['openid-client'],async headers(){return [{source:'/:path*',headers:[{key:'X-Content-Type-Options',value:'nosniff'},{key:'Referrer-Policy',value:'same-origin'},{key:'X-Frame-Options',value:'DENY'},{key:'Permissions-Policy',value:'camera=(), microphone=(), geolocation=()'},{key:'Content-Security-Policy',value:contentSecurityPolicy(process.env.NODE_ENV==='development')}]}]}}
export default config
