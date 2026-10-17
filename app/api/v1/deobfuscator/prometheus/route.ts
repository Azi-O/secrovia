import { NextResponse } from 'next/server'

export const runtime = 'nodejs'

export function GET() {
  return new Response('cl cl cl', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => null)
  if (!body || typeof body.code !== 'string' || !body.code.trim()) return NextResponse.json({ error: 'code is required' }, { status: 400 })
  try {
    const { deobfuscate } = require('../../../../../lib/prometheus/index.js') as { deobfuscate: (source: string, options?: Record<string, unknown>) => { code: string; warnings: unknown[]; notes: unknown[] } }
    const result = deobfuscate(body.code, { name: 'api-input' })
    return NextResponse.json({ code: result.code, warnings: result.warnings, notes: result.notes })
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Prometheus deobfuscation failed' }, { status: 422 })
  }
}
