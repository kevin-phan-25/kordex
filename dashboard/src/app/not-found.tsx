import Link from 'next/link'
export default function NotFound(){return <main className="error-page"><div className="eyebrow">OPERATIONS / NOT FOUND</div><h1 className="page-title">This record is unavailable</h1><p className="page-subtitle">It may have been removed or belong to another organization.</p><Link className="button primary" href="/overview">Return to overview</Link></main>}
