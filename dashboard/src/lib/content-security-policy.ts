export function contentSecurityPolicy(isDevelopment: boolean): string {
  const developmentEval = isDevelopment ? " 'unsafe-eval'" : ''
  return `default-src 'self'; script-src 'self' 'unsafe-inline'${developmentEval}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';`
}
