import type {Metadata} from 'next'
import './globals.css'
export function generateMetadata():Metadata{const brand=process.env.KORDEX_PRODUCT_NAME?.trim()||'Kordex';return {title:{default:`Fleet overview | ${brand}`,template:`%s | ${brand}`},description:'Infrastructure operations and safe Kubernetes maintenance campaigns.'}}
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>}
