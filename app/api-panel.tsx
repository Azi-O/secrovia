'use client'

import { useState } from 'react'
import { BookOpen, Copy, KeyRound, RefreshCw } from 'lucide-react'
import { resetApiToken } from '@/app/actions/api-tokens'
import { apiServices, type ApiServiceKey } from '@/lib/api-services'

type ServiceKey = ApiServiceKey

export function ApiPanel({ service, token, onToken }: { service: ServiceKey; token: string | null; onToken: (token: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const info = apiServices[service]
  const isObfuscator = service === 'obfuscator'
  const readmePath = '/discord-bot-readme.md'

  async function createToken() {
    setBusy(true)
    setError('')
    try { onToken(await resetApiToken(service)) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to save API token') } finally { setBusy(false) }
  }

  async function copy(value: string) { await navigator.clipboard?.writeText(value) }

  return <section className="api-panel-shell">
    <div className="api-panel-hero"><div><p className="eyebrow">Developer API</p><h1>{info.label}</h1><p>Personal access for your Secrovia automation and Discord bot workflows.</p></div><span className="api-status"><KeyRound size={16} /> API token required</span></div>
    <div className="api-token-card">
      <div className="api-token-heading"><div><span className="api-label">Endpoint</span><code>{info.path}</code></div><button className="secondary-button" onClick={() => void copy(info.path)}><Copy size={15} /> Copy</button></div>
      <div className="api-token-heading"><div className="api-token-value"><span className="api-label">Token</span><code>{token ?? 'No token created yet'}</code></div><div className="api-actions"><button className="primary-button" onClick={() => void createToken()} disabled={busy}>{busy ? 'Creating...' : token ? 'Reset token' : 'Create token'}<RefreshCw size={15} /></button>{token && <button className="secondary-button" onClick={() => void copy(token)}><Copy size={15} /> Copy token</button>}</div></div>
      {error && <p className="form-error" role="alert">{error}</p>}
    </div>
    <div className="api-guide"><div className="api-guide-title"><BookOpen size={18} /><strong>Usage guide</strong></div><p>{isObfuscator ? 'Send source code or a source link to the API to receive the obfuscated result.' : 'Send a source file or link to the API. Your bot can return the processed output to Discord.'}</p>
      {isObfuscator && <div className="api-command-list"><div><code>Debug</code><span>Select the debug level before sending the code.</span></div><div><code>Medium</code><span>Select the medium level before sending the code.</span></div><div><code>Maximum</code><span>Select the maximum level before sending the code.</span></div><small>The API cannot identify which Discord command was used. Your bot must store the selected level and include it in the request payload, for example with a <code>level</code> field.</small></div>}
      <pre>{`curl -X POST https://secrovia.vercel.app${info.path} \\\n  -H "Authorization: Bearer ${token ?? 'YOUR_API_TOKEN'}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"code":"..."}'`}</pre>
      <div className="api-discord-example"><span>Discord bot README</span><a href={readmePath} download="secrovia-discord-bot-readme.md" className="api-readme-link">{readmePath}</a><small>Download the English README for creating a Discord bot, registering a custom command, reading files or links, calling the API, and returning the output.</small></div>
    </div>
  </section>
}
