'use client'

import { useState } from 'react'
import { ArrowRight, BookOpen, Copy, KeyRound, RefreshCw } from 'lucide-react'
import { resetApiToken } from '@/app/actions/api-tokens'
import { apiServices, type ApiServiceKey } from '@/lib/api-services'

type ServiceKey = ApiServiceKey

export function ApiPanel({ service, token, onToken }: { service: ServiceKey; token: string | null; onToken: (token: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const info = apiServices[service]
  async function createToken() { setBusy(true); setError(''); try { onToken(await resetApiToken(service)) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to save API token') } finally { setBusy(false) } }
  async function copy(value: string) { await navigator.clipboard?.writeText(value) }
  const command = service === 'obfuscator' ? '.Obf1 [file-or-link]' : '.god [file-or-link]'
  return <section className="api-panel-shell"><div className="api-panel-hero"><div><p className="eyebrow">Developer API</p><h1>{info.label}</h1><p>Personal access for your Secrovia automation and Discord bot workflows.</p></div><span className="api-status"><KeyRound size={16} /> Per-user token</span></div><div className="api-token-card"><div className="api-token-heading"><div><span className="api-label">Endpoint</span><code>{info.path}</code></div><button className="secondary-button" onClick={() => void copy(info.path)}><Copy size={15} /> Copy</button></div><div className="api-token-heading"><div className="api-token-value"><span className="api-label">Token</span><code>{token ?? 'No token created yet'}</code></div><div className="api-actions"><button className="primary-button" onClick={() => void createToken()} disabled={busy}>{busy ? 'Creating...' : token ? 'Reset token' : 'Create token'}<RefreshCw size={15} /></button>{token && <button className="secondary-button" onClick={() => void copy(token)}><Copy size={15} /> Copy token</button>}</div></div>{error && <p className="form-error" role="alert">{error}</p>}</div><div className="api-guide"><div className="api-guide-title"><BookOpen size={18} /><strong>Usage guide</strong></div><p>Send a POST request with your token and source code. The API returns the processed output for your bot or tool.</p><pre>{`curl -X POST https://secrovia.vercel.app${info.path} \\\n  -H "Authorization: Bearer ${token ?? 'Secrovia-your-token'}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"code":"..."}'`}</pre><div className="api-discord-example"><span>Discord example</span><code>{command}</code><small>Bot fetches the file or link, sends code to this API, then returns the output in chat.</small></div></div><button className="back-button api-back" onClick={() => window.dispatchEvent(new CustomEvent('workspace:navigate', { detail: 'dashboard' }))}><ArrowRight size={15} className="rotate-180" /> Back to dashboard</button></section>
}
