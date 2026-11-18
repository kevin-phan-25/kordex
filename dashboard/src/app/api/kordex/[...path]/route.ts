import {NextRequest} from 'next/server'
import {apiURL, appURL, getSession} from '../../../../lib/auth'
import {proxyManagementRequest} from '../../../../lib/proxy'

async function proxy(request: NextRequest, {params}: {params: Promise<{path: string[]}>}) {
  const {path} = await params
  return proxyManagementRequest(request, path, {apiURL, appURL, getSession})
}
export const GET = proxy
export const POST = proxy
export const PUT = proxy
