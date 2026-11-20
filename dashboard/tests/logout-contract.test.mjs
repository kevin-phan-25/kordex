import assert from 'node:assert/strict'
import {test} from 'node:test'
import {buildKeycloakLogoutURL,logoutCompletionRedirect,postLogoutRedirect,validateEndSessionMetadata} from '../src/lib/logout-contract.ts'
import {expireAuthCookies} from '../src/lib/oidc-contract.ts'

const appURL='http://127.0.0.1:3000'
const issuer='https://keycloak.localhost:8443/realms/kordex'
const endpoint=`${issuer}/protocol/openid-connect/logout`
test('local logout invalidates the session and transaction cookies with matching cookie attributes',()=>{
  const values=new Map([['kordex_dev_session','encrypted'],['kordex_dev_state','state'],['kordex_dev_pkce','verifier'],['kordex_dev_nonce','nonce']])
  const writes=[]
  const store={set(name,value,options){values.set(name,value);writes.push({name,value,options})}}
  const names=kind=>`kordex_dev_${kind}`
  expireAuthCookies(store,appURL,'development',names)
  assert.equal(values.get('kordex_dev_session'),'')
  assert.equal(writes.length,4)
  for(const {options} of writes){
    assert.equal(options.path,'/')
    assert.equal(options.httpOnly,true)
    assert.equal(options.secure,false)
    assert.equal(options.sameSite,'lax')
    assert.equal(options.maxAge,0)
    assert.equal(options.expires.getTime(),0)
  }
})

test('post-logout redirect is restricted to the configured login page and approved status query',()=>{
  assert.equal(postLogoutRedirect(appURL,`${appURL}/login`),`${appURL}/login`)
  assert.equal(postLogoutRedirect(appURL,`${appURL}/login?error=session_revocation_failed`),`${appURL}/login?error=session_revocation_failed`)
  for(const value of ['https://attacker.example/login',`${appURL}/other`,`${appURL}/login?next=https://attacker.example`,`${appURL}/login#outside`])
    assert.throws(()=>postLogoutRedirect(appURL,value),/Invalid post-logout redirect/)
})

test('missing and expired sessions complete through the fixed login redirect without API-revocation failure',()=>{
  assert.equal(logoutCompletionRedirect(appURL,false,true),`${appURL}/login`)
  const expiredSession=null
  assert.equal(logoutCompletionRedirect(appURL,Boolean(expiredSession),true),`${appURL}/login`)
  assert.equal(logoutCompletionRedirect(appURL,true,false),`${appURL}/login?error=session_revocation_failed`)
})

test('Keycloak RP logout URL uses client_id, fixed redirect, and no ID token',()=>{
  const url=new URL(buildKeycloakLogoutURL({appURL,issuer,endSessionEndpoint:endpoint,clientId:'kordex-dashboard',postLogoutRedirectURI:`${appURL}/login`}))
  assert.equal(url.origin,'https://keycloak.localhost:8443')
  assert.equal(url.pathname,'/realms/kordex/protocol/openid-connect/logout')
  assert.equal(url.searchParams.get('client_id'),'kordex-dashboard')
  assert.equal(url.searchParams.get('post_logout_redirect_uri'),`${appURL}/login`)
  assert.equal(url.searchParams.has('id_token_hint'),false)
  assert.equal(url.href.includes('id-token'),false)
  assert.throws(()=>buildKeycloakLogoutURL({appURL,issuer,endSessionEndpoint:'https://attacker.example/realms/kordex/protocol/openid-connect/logout',clientId:'kordex-dashboard',postLogoutRedirectURI:`${appURL}/login`}),/Invalid OIDC end-session endpoint/)
})

test('logout discovery requires the exact configured issuer and an advertised endpoint',()=>{
  assert.equal(validateEndSessionMetadata(issuer,{issuer,end_session_endpoint:`${issuer}/protocol/openid-connect/logout`}),`${issuer}/protocol/openid-connect/logout`)
  assert.throws(()=>validateEndSessionMetadata(issuer,{issuer:'https://attacker.invalid',end_session_endpoint:`${issuer}/protocol/openid-connect/logout`}))
  assert.throws(()=>validateEndSessionMetadata(issuer,{issuer}))
})

test('repeated local logout expiration is idempotent',()=>{
  const writes=[]
  const store={set:(...args)=>writes.push(args)}
  const name=kind=>`kordex_dev_${kind}`
  expireAuthCookies(store,appURL,'development',name)
  expireAuthCookies(store,appURL,'development',name)
  assert.equal(writes.length,8)
})
