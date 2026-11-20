import {Mark} from '../../components/brand'
import {appURL,publicBrand} from '../../lib/auth'
export const metadata={title:'Sign in'}
export default async function Login({searchParams}:{searchParams:Promise<{error?:string}>}){
  const q=await searchParams,value=q.error??''
  const messages:Record<string,string>={
    access_denied:'Your account has no organization access. Ask an organization administrator to add your OIDC subject.',
    organization_access_denied:'You authenticated successfully, but no Kordex organization membership is assigned to this account. Ask an organization administrator for access.',
    api_auth_rejected:'Keycloak authenticated you, but the control plane rejected the identity token. Ask the Kordex administrator to verify the API issuer and audience configuration.',
    api_unavailable:'Authentication completed, but the Kordex control plane could not be reached. Check that the OIDC API is running and try again.',
    identity_mismatch:'The identity returned by the provider did not match the control-plane identity. Sign in again; if this repeats, contact the Kordex administrator.',
    oidc_response_rejected:'Keycloak returned a response the dashboard could not validate. Start a new sign-in attempt. If it repeats, check the sanitized dashboard and Keycloak logs for the callback stage.',
    transaction_cookie_missing:'The sign-in transaction expired or the browser changed host names. Open the configured dashboard URL and start sign-in again.',
    token_response_invalid:'Keycloak did not return the required identity token. Check the realm client and token configuration.',
    provider_returned_error:'Keycloak did not complete sign-in. Start a new attempt or check the provider status.',
    session_creation_failed:'Sign-in was validated, but the dashboard could not create a session. Check the dashboard session-secret configuration and logs.',
    session_expired:'Your dashboard session is missing or expired. Sign in again.',
    configuration:'Sign in is not configured. Check the dashboard OIDC environment values.',
    oidc_unavailable:'The dashboard could not contact or validate the Keycloak provider. Check local CA trust and the configured issuer, then try again.',
    session_revocation_failed:'This dashboard session ended, but the management API could not confirm token revocation. Contact your administrator if the credential may be exposed.',
    provider_logout_unavailable:'Your Kordex session was cleared, but the identity provider logout could not be started. Sign in again only if you intended to continue.',
  }
  const message=messages[value]??(value?'Sign in could not be completed. Start a new attempt; if it repeats, check the sanitized authentication-stage logs.':'')
  return <main className="login-shell"><section className="login-card"><div className="brand"><Mark/>{publicBrand()}</div><div className="eyebrow">Infrastructure operations</div><h1>Welcome back</h1><p>Sign in with your organization account to inspect fleet health, review maintenance campaigns, and approve safe operations.</p>{message&&<div className="banner error" role="alert">{message}</div>}<a className="button primary" href={`${appURL()}/api/auth/login`} style={{width:'100%',padding:'11px'}}>Continue with your organization</a><div className="login-meta">Your session is protected with secure, HTTP-only cookies.</div></section></main>
}
