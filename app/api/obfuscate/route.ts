import { NextResponse } from 'next/server'

export async function POST(request: Request) {
  try {
    const { code } = await request.json()
    if (typeof code !== 'string' || !code.trim()) {
      return NextResponse.json({ error: 'Code is required' }, { status: 400 })
    }

    const upstream = await fetch('https://wearedevs.net/api/obfuscate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/plain, */*' },
      body: JSON.stringify({ code }),
      cache: 'no-store',
    })
    const responseText = await upstream.text()
    if (!upstream.ok) return NextResponse.json({ error: 'Obfuscator API request failed' }, { status: 502 })

    let obfuscated = responseText
    try {
      const data = JSON.parse(responseText) as { code?: string; result?: string; output?: string }
      obfuscated = data.code ?? data.result ?? data.output ?? responseText
    } catch {
      // The upstream may return the obfuscated source as plain text.
    }

    const watermark = 'This file was created by Secrovia via the API https://discord.gg/JqNpxc8QXk'
    obfuscated = obfuscated.replace(/^\s*--\[\[\s*v1\.0\.0\s+https:\/\/wearedevs\.net\/obfuscator\s*\]\]\s*/i, '')
    return NextResponse.json({ code: `-- ${watermark}\n${obfuscated}` })
  } catch {
    return NextResponse.json({ error: 'Unable to obfuscate code' }, { status: 500 })
  }
}
